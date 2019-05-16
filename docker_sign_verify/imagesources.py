#!/usr/bin/env python

"""Classes that provide a source of docker images."""

import abc
import copy
import datetime
import hashlib
import io
import json
import logging
import os
import random
import subprocess
import tempfile
import time

from pathlib import Path
from typing import Dict
from urllib.parse import urlparse

import gnupg  # Needed for type checking
import requests
from requests.models import Response
import www_authenticate

from .manifests import (
    ArchiveManifest,
    DeviceMapperRepositoryManifest,
    Manifest,
    RegistryV2Manifest,
)
from .imageconfig import ImageConfig
from .imagename import ImageName
from .signers import Signer
from .utils import (
    copy_file,
    file_exists_in_tar,
    formatted_digest,
    gunzip,
    must_be_equal,
    read_file,
    tar,
    tar_add_file,
    tar_delete_file,
    tar_mkdir,
    untar,
    write_file,
    xellipsis,
    FormattedSHA256,
)

LOGGER = logging.getLogger(__name__)


class ImageSource(abc.ABC):
    """
    Abstract source of docker images.
    """

    def __init__(self, *, dry_run: bool = False):
        """
        Args:
            dry_run: If true, destination image sources will not be changed.
        """
        self.dry_run = dry_run

    def _sign_image_config(self, signer: Signer, image_name: ImageName) -> Dict:
        """
        Verifies an image, then signs it without storing it in the image source.

        Args:
            signer: The signer used to create the signature value.
            image_name: The image name.

        Returns:
            dict:
                image_config: The ImageConfig object corresponding to the signed image.
                signature_value: as defined by :func:~docker_sign_verify.ImageConfig.sign.
                verify_image_data: as defined by :func:~docker_sign_verify.ImageSource.verify_image_integrity.
        """
        # Verify image integrity (we use the verified values from this point on)
        data = self.verify_image_integrity(image_name)
        image_config = data["image_config"]  # type: ImageConfig

        # Append our signature to any existing signatures ....
        signature_value = image_config.sign(signer)

        return {
            "image_config": image_config,
            "signature_value": signature_value,
            "verify_image_data": data,
        }

    def _unsign_image_config(self, image_name: ImageName) -> Dict:
        """
        Verifies an image, then removes all signature values without storing it in the image source.

        Args:
            image_name: The image name.

        Returns:
                image_config: The ImageConfig object corresponding to the unsigned image.
                verify_image_data: as defined by :func:~docker_sign_verify.ImageSource.verify_image_integrity.
        """
        # Verify image integrity (we use the verified values from this point on)
        data = self.verify_image_integrity(image_name)
        image_config = data["image_config"]  # type: ImageConfig

        # Remove all existing signatures ....
        image_config.unsign()

        return {"image_config": image_config, "verify_image_data": data}

    def _verify_image_config(self, image_name: ImageName) -> Dict:
        """
        Verifies the integration of an image configuration against metadata contained within a manifest.

        Args:
            image_name: The image name for which to retrieve the configuration.

        Returns:
            dict:
                image_config: The image configuration.
                image_layers: The listing of image layer identifiers.
                manifest: The image-source specific manifest.
                manifest_layers: The listing of manifest layer identifiers.
        """

        # Retrieve the image configuration digest and layers identifiers from the manifest ...
        LOGGER.debug("Verifying Integrity: %s ...", image_name)
        manifest = self.get_manifest(image_name)
        config_digest = manifest.get_config_digest(image_name)
        LOGGER.debug("    config digest: %s", xellipsis(config_digest))
        manifest_layers = manifest.get_layers(image_name)
        LOGGER.debug(
            "    manifest layers:\n\t\t\t%s",
            "\n\t\t\t".join([xellipsis(l) for l in manifest_layers]),
        )

        # Retrieve the image layers from the image configuration ...
        image_config = self.get_image_config(image_name)
        must_be_equal(
            config_digest,
            image_config.get_config_digest(),
            "Image config digest mismatch (1)",
        )
        image_layers = image_config.get_image_layers()
        LOGGER.debug(
            "    image layers:\n\t\t\t%s",
            "\n\t\t\t".join([xellipsis(l) for l in image_layers]),
        )

        # Quick check: Ensure that the layer counts are consistent
        must_be_equal(len(manifest_layers), len(image_layers), "Layer count mismatch")

        return {
            "image_config": image_config,
            "image_layers": image_layers,
            "manifest": manifest,
            "manifest_layers": manifest_layers,
        }

    @abc.abstractmethod
    def get_image_config(self, image_name: ImageName) -> ImageConfig:
        """
        Retrieves an image configuration (config.json).

        Args:
            image_name: The image name.

        Returns:
            The image configuration.
        """

    @abc.abstractmethod
    # TODO: Can we make layer type 'FormattedSHA256' ???
    def get_image_layer_to_disk(self, image_name: ImageName, layer: str, file):
        """
        Retrieves a single image layer stored to disk.

        Args:
            image_name: The image name.
            layer: The layer identifier in the form: <hash type>:<digest value>.
            file: File in which to store the image layer.
        """

    @abc.abstractmethod
    def get_manifest(self, image_name: ImageName = None) -> Manifest:
        """
        Retrieves the manifest for a given image.

        Args:
            image_name: The name image for which to retrieve the manifest.

        Returns:
            The image source-specific manifest.
        """

    @abc.abstractmethod
    def put_manifest(self, manifest: Manifest, image_name: ImageName = None):
        """
        Assigns the manifest for a given image.

        Args:
            manifest: The image source-specific manifest to be assigned.
            image_name: The name of the image for which to assign the manifest.
        """

    @abc.abstractmethod
    def put_image_config(self, image_name: ImageName, image_config: ImageConfig):
        """
        Assigns an image configuration (config.json).

        Args:
            image_name: The image name.
            image_config: The image configuration to be assigned.
        """

    @abc.abstractmethod
    def put_image_layer(self, image_name: ImageName, content):
        """
        Assigns a single image layer.

        Args:
            image_name: The image name.
            content: The layer content.
        """

    @abc.abstractmethod
    def put_image_layer_from_disk(self, image_name: ImageName, file):
        """
        Assigns a single image layer read from disk.

        Args:
            image_name: The image name.
            file: File from which to read the layer content.
        """

    @abc.abstractmethod
    def layer_exists(self, image_name: ImageName, layer: FormattedSHA256) -> bool:
        """
        Checks if a given image layer exists.

        Args:
            image_name: The image name.
            layer: The layer identifier in the form: <hash type>:<digest value>.

        Returns:
            bool: True if the layer exists, False otherwise.
        """

    @abc.abstractmethod
    def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source,
        dest_image_name: ImageName,
    ):
        """
        Retrieves, verifies and signs the image, storing it in the destination image source.

        Args:
            signer: The signer used to create the signature value.
            src_image_name: The source image name.
            dest_image_source: The destination image source into which to store the signed image.
            dest_image_name: The description image name.

        Returns:
            dict: as defined by :func:~docker_sign_verify.ImageSource._sign_image_config.
        """

    @abc.abstractmethod
    def unsign_image(
        self, src_image_name: ImageName, dest_image_source, dest_image_name: ImageName
    ):
        """
            Retrieves and unsigns an image, storing it in the destination image source.

        Args:
            src_image_name: The source image name.
            dest_image_source: The destination image source into which to store the unsigned image.
            dest_image_name: The description image name.

        Returns:
            dict: as defined by :func:~docker_sign_verify.ImageSource.TODO.
        """

    @abc.abstractmethod
    def verify_image_integrity(self, image_name: ImageName):
        """
        Verifies that the image source data format is consistent with respect to the image configuration and image
        layers, and that the image configuration and image layers are internally consistent (the digest values match).

        Args:
            image_name: The image name.

        Returns:
            dict:
                image config: The image configuration.
                manifest: The image source-specific manifest file (archive, registry, repository).
                uncompressed_layer_files: The list of uncompressed layer files on disk.
        """

    def verify_image_signatures(self, image_name: ImageName):
        """
        Verifies that signatures contained within the image source data format are valid (that the image has not been
        modified since they were created)

        Args:
            image_name: The image name.
        """

        # Verify image integrity (we use the verified values from this point on)
        image_config = self.verify_image_integrity(image_name)["image_config"]

        # Verify image signatures ...
        LOGGER.debug("Verifying Signature(s): %s ...", image_name)
        LOGGER.debug(
            "    config digest (signed): %s",
            xellipsis(image_config.get_config_digest()),
        )
        data = image_config.verify_signatures()
        signature_data = data["signature_data"]
        LOGGER.debug(
            "    config digest (unsigned): %s",
            xellipsis(signature_data["original_config"]),
        )

        # List the image signatures ...
        LOGGER.debug("    signatures:")
        for result in data["results"]:
            # pylint: disable=protected-access
            if isinstance(result, gnupg._parsers.Verify):
                if not result.valid:
                    raise RuntimeError(
                        "Verification failed for signature with key_id '{0}': {1}".format(
                            result.key_id, result.status
                        )
                    )
                LOGGER.debug(
                    "        Signature made %s using key ID %s",
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.gmtime(float(result.sig_timestamp))
                    ),
                    result.key_id,
                )
                LOGGER.debug("            %s", result.username)
            elif result.get("type", None) == "pki":
                if not result["valid"]:
                    raise RuntimeError(
                        "Verification failed for signature using cert: {0}".format(
                            result["keypair_path"]
                        )
                    )
                # TODO: Add better debug logging
                LOGGER.debug("        Signature made using undetailed PKI keypair.")
            else:
                LOGGER.error("Unknown Signature Type: %s", type(result))

        LOGGER.debug("Signature check passed.")


class ArchiveImageSource(ImageSource):
    """
    Docker archive image source.
    """

    FILE_ARCHIVE_MANIFEST = "manifest.json"
    CHUNK_SIZE = 4096

    def __init__(self, *, archive, **kwargs):
        """
        Args:
            archive: Path to the docker image archive.
        """
        super(ArchiveImageSource, self).__init__(**kwargs)
        self.archive = archive

    def _file_exists(self, name) -> bool:
        """
        Checks if a give file exists within this image source.

        Args:
            name: Name of the file to be checked.

        Returns:
            bool: True if the file exists, False otherwise.
        """
        with open(self.archive, "rb") as file_in:
            return file_exists_in_tar(file_in, name)

    def get_file_from_archive(self, path):
        """
        Retrieves a file from within this image source.

        Args:
            path: Relative path of the file to be retrieved.

        Returns:
            The file content.
        """
        bytesio = io.BytesIO()
        with open(self.archive, "rb") as file:
            untar(file, path, bytesio)
        return bytesio.read()

    # ImageSource Members

    def get_image_config(self, image_name: ImageName) -> ImageConfig:
        config = self.get_manifest().get_config(image_name)
        return ImageConfig(self.get_file_from_archive(config["Config"]))

    def get_image_layer_to_disk(self, image_name: ImageName, layer: str, file):
        with open(self.archive, "rb") as file_in:
            return untar(file_in, ArchiveManifest.digest_to_layer(layer), file)

            #    def put_image_layer(self, image, content):

    def get_manifest(self, image_name: ImageName = None) -> Manifest:
        raw_archive_manifest = self.get_file_from_archive(
            ArchiveImageSource.FILE_ARCHIVE_MANIFEST
        )
        return ArchiveManifest(raw_archive_manifest)

    def put_image_config(self, image_name: ImageName, image_config: ImageConfig):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_config")
            return
        digest = image_config.get_config_digest()
        name = "{0}.json".format(digest.sha256)
        if not self._file_exists(name):
            with open(self.archive, "rb+") as file_out:
                tar_add_file(file_out, name, image_config.get_config())

    def put_image_layer(self, image_name: ImageName, content):
        raise NotImplementedError

    def put_image_layer_from_disk(self, image_name: ImageName, file) -> FormattedSHA256:
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer_from_disk")
            return FormattedSHA256("0" * 64)
        # TODO: Do we really want to use random garbage here???
        #       Look into moby/.../save.go to find what to use instead.
        digest = formatted_digest(
            "{0}{1}{2}".format(
                str(image_name), datetime.datetime.now(), random.randint(1, 101)
            ).encode("utf-8")
        )
        layer = ArchiveManifest.digest_to_layer(digest)
        with open(self.archive, "rb+") as file_out:
            tar_mkdir(file_out, os.path.dirname(layer))
            file_out.seek(0)
            tar(file_out, layer, file)
        return digest

    def put_manifest(self, manifest: Manifest, image_name: ImageName = None):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_manifest")
            return
        with open(self.archive, "rb+") as file_out:
            tar_delete_file(file_out, ArchiveImageSource.FILE_ARCHIVE_MANIFEST)
            file_out.seek(0)
            tar_add_file(
                file_out,
                ArchiveImageSource.FILE_ARCHIVE_MANIFEST,
                str(manifest).encode("utf-8"),
            )

    def layer_exists(self, image_name: ImageName, layer: FormattedSHA256) -> bool:
        return self._file_exists(ArchiveManifest.digest_to_layer(layer))

    def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source: ImageSource,
        dest_image_name: ImageName,
    ):
        LOGGER.debug("Signing: %s ...", src_image_name)

        # Generate a signed image configuration ...
        data = self._sign_image_config(signer, src_image_name)
        manifest = data["verify_image_data"]["manifest"]
        LOGGER.debug("    Signature:\n%s", data["signature_value"])
        image_config = data["image_config"]

        # Replicate all of the image layers ...
        archive_layers = manifest.get_layers(src_image_name)
        archive_layers_changed = archive_layers.copy()
        for i, archive_layer in enumerate(archive_layers):
            if not dest_image_source.layer_exists(dest_image_name, archive_layer):
                # Update the layer
                digest = dest_image_source.put_image_layer_from_disk(
                    dest_image_name,
                    data["verify_image_data"]["uncompressed_layer_files"][i],
                )
                archive_layers_changed[i] = digest
        archive_layers = archive_layers_changed

        # Push the new image configuration ...
        config_digest_signed = image_config.get_config_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest_signed)
        dest_image_source.put_image_config(dest_image_name, image_config)

        # Generate a new archive manifest, and push ...
        if isinstance(dest_image_source, ArchiveImageSource):
            manifest_signed = dest_image_source.get_manifest()  # type: ArchiveManifest

            repotags = None
            if dest_image_name.tag:
                repotags = [str(dest_image_name)]
                manifest_signed.append_config(
                    config_digest_signed, archive_layers, repotags
                )
            data["manifest_signed"] = manifest_signed
            # TODO: make sure to remove conflicting tags in "other" config entries
            dest_image_source.put_manifest(manifest_signed)
            # TODO: Update foo.tar:/repositories as well
        elif isinstance(dest_image_source, RegistryV2ImageSource):
            raise NotImplementedError
        elif isinstance(dest_image_source, DeviceMapperRepositoryImageSource):
            raise NotImplementedError
        else:
            raise RuntimeError(
                "Unknown derived class: {0}".format(type(dest_image_source))
            )

        LOGGER.debug("Created new image: %s", dest_image_name)

        return data

    def unsign_image(
        self, src_image_name: ImageName, dest_image_source, dest_image_name: ImageName
    ):
        raise NotImplementedError

    def verify_image_integrity(self, image_name: ImageName):
        data = self._verify_image_config(image_name)

        # Reconcile manifest layers and image layers (in order)...
        uncompressed_layer_files = []
        for i, layer in enumerate(data["manifest_layers"]):
            # Retrieve the archive image layer and verify the digest ...
            uncompressed_layer_files.append(tempfile.NamedTemporaryFile())
            data_uncompressed = self.get_image_layer_to_disk(
                image_name, layer, uncompressed_layer_files[i]
            )
            must_be_equal(
                data["image_layers"][i],
                data_uncompressed["digest"],
                "Archive layer[{0}] digest mismatch".format(i),
            )

        LOGGER.debug("Integrity check passed.")

        return {
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": uncompressed_layer_files,
        }


class RegistryV2ImageSource(ImageSource):
    """
    Docker registry image source.
    """

    BLOB_MIME_TYPE = "application/vnd.docker.container.image.v1+json"
    BLOB_URL_PATTERN = "https://{0}/v2/{1}/blobs/{2}"
    DOCKERHUB_AUTH_URL_PATTERN = (
        "{0}?service={1}&scope={2}&client_id=docker-sign-verify"
    )
    MANIFEST_MIME_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
    MANIFEST_URL_PATTERN = "https://{0}/v2/{1}/manifests/{2}"

    DEFAULT_CREDENTIALS_STORE = Path.home().joinpath(".docker/config.json")

    CHUNK_SIZE = 4096

    def __init__(self, *, credentials_store=None, **kwargs):
        """
        Args:
            credentials_store: Path to the docker registry credentials store.
        """
        super(RegistryV2ImageSource, self).__init__(**kwargs)
        if not credentials_store:
            credentials_store = os.environ.get(
                "DSV_CREDENTIALS_STORE", RegistryV2ImageSource.DEFAULT_CREDENTIALS_STORE
            )
        self.credentials_store = credentials_store
        self.credentials = None
        self.token = None

    def _get_auth_token(self, credentials: str, endpoint: str, scope: str) -> str:
        """
        Retrieves the registry auth token for a given scope.

        Args:
            credentials: The credentials to use to retrieve the auth token.
            endpoint: Registry endpoint for which to retrieve the token.
            scope: The scope of the auth token.

        Returns:
            The corresponding auth token, or None.
        """

        # https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md
        if not self.token:
            # Test using HTTP basic authentication to retrieve the www-authenticate response header ...
            headers = {"Authorization": "Basic {0}".format(credentials)}
            url = "https://{0}/v2/".format(endpoint)
            response = requests.get(url, headers=headers)

            auth_params = www_authenticate.parse(response.headers["Www-Authenticate"])
            bearer = auth_params["bearer"]

            url = RegistryV2ImageSource.DOCKERHUB_AUTH_URL_PATTERN.format(
                bearer["realm"], bearer["service"], scope
            )
            response = requests.get(url, headers=headers)
            #LOGGER.debug("Token Response: %s", response.content)
            must_be_equal(200, response.status_code, "Failed to retrieve bearer token")

            self.token = response.json()["token"]

        return self.token

    def _get_credentials(self, endpoint: str) -> str:
        """
        Retrieves the registry credentials from the docker registry credentials store for a given endpoint

        Args:
            endpoint: Registry endpoint for which to retrieve the credentials.

        Returns:
            The corresponding base64 encoded registry credentials, or None.
        """
        result = None

        if not self.credentials and self.credentials_store:
            LOGGER.debug("Using credentials store: %s", self.credentials_store)

            # TODO: Add support for secure providers:
            #       https://docs.docker.com/engine/reference/commandline/login/#credentials-store

            self.credentials = {}
            if self.credentials_store.is_file():
                with self.credentials_store.open(mode="rb") as file:
                    self.credentials = json.loads(file.read()).get("auths", {})

        for endpoint_auth in [
            u
            for u in self.credentials
            if u == endpoint or urlparse(u).netloc == endpoint
        ]:
            result = self.credentials[endpoint_auth].get("auth", None)
            if result:
                break

        return result

    def _get_request_headers(self, image_name: ImageName, headers=None):
        """
        Generates request headers that contain registry credentials for a given registry endpoint.

        Args:
            image_name: Image name for which to retrieve the request headers.
            headers: Optional supplemental request headers to be returned.

        Returns:
            The generated request headers.
        """
        if not headers:
            headers = {}

        endpoint = image_name.resolve_endpoint()
        credentials = self._get_credentials(endpoint)
        if credentials:
            if "docker.io" in endpoint:
                token = self._get_auth_token(
                    credentials,
                    endpoint,
                    "repository:{0}:pull".format(image_name.resolve_image()),
                )
                headers["Authorization"] = "Bearer {0}".format(token)
            else:
                headers["Authorization"] = "Basic {0}".format(credentials)

        return headers

    def monolithic_blob_upload(
        self, image_name: ImageName, blob, digest: FormattedSHA256 = None
    ) -> Response:
        """
        Performs a monolithic upload of an image blob.

        Args:
            image_name: The name of the target repository.
            blob: The data to be uploaded.
            digest: Digest of uploaded blob.

        Returns:
            The underlying response.
        """
        url = RegistryV2ImageSource.BLOB_URL_PATTERN.format(
            image_name.resolve_endpoint(), image_name.resolve_image(), "uploads/"
        )
        headers = self._get_request_headers(
            image_name, {"Content-Type": "application/octet-stream"}
        )
        if not digest:
            digest = formatted_digest(blob)
        response = requests.post(
            url, params={"digest": digest}, headers=headers, data=blob
        )
        must_be_equal(202, response.status_code, "Failed to upload blob")

        # TODO: Do we need to emulate the Docker-Content-Digest return type?
        LOGGER.fatal("HEADERS: %s", response.headers)
        return response

    def initiate_resumable_blob_upload(self, image_name: ImageName) -> Response:
        """
        Starts a resumable upload of an image blob.

        Args:
            image_name: The name of the target repository.

        Returns:
            The underlying response.
        """
        url = RegistryV2ImageSource.BLOB_URL_PATTERN.format(
            image_name.resolve_endpoint(), image_name.resolve_image(), "uploads/"
        )
        headers = self._get_request_headers(image_name)
        response = requests.post(url, headers=headers)
        # logging.debug("UUID: {0}".format(response.headers["Docker-Upload-UUID"]))
        must_be_equal(
            202, response.status_code, "Failed to initiate resumable blob upload"
        )
        return response

    def resume_blob_upload(self, location, offset, chunk) -> Response:
        """
        Continues a resumable upload of an image blob.

        Args:
            location:
                The Resumable location provided from
                :func:~docker_sign_verify.RegistryV2ImageSource.initiate_resumable_blob_upload.
            offset: Range of bytes identifying the desired block of content represented by the body.
            chunk: The chunk of data to be uploaded.

        Returns:
            TODO
        """
        headers = self._get_request_headers(
            ImageName.parse(urlparse(location).netloc + "/"),
            {
                "Content-Range": "{0}-{1}".format(offset, offset + len(chunk) - 1),
                "Content-Type": "application/octet-stream",
            },
        )
        response = requests.patch(location, headers=headers, data=chunk)
        must_be_equal(202, response.status_code, "Failed to upload blob chunk")

        return response

    def complete_resumable_blob_upload(
        self, location, digest: FormattedSHA256, chunk=None
    ) -> FormattedSHA256:
        """
        Finishes a resumable upload of an image blob.

        Args:
            location:
                The Resumable location provided from
                :func:~docker_sign_verify.RegistryV2ImageSource.initiate_resumable_blob_upload.
            digest: Digest of uploaded blob.
            chunk: The chunk of data to be uploaded.

        Returns:
            FormattedSHA256: Digest of the targeted content for the request.
        """
        headers = self._get_request_headers(
            ImageName.parse(urlparse(location).netloc + "/"),
            {"Content-Type": "application/octet-stream"},
        )
        response = requests.put(
            location, params={"digest": digest}, headers=headers, data=chunk
        )
        must_be_equal(
            201, response.status_code, "Failed to complete resumable blob upload"
        )

        return FormattedSHA256.parse(response.headers["Docker-Content-Digest"])

    # TODO: Re-implement or remove this and use get_image_layer_to_disk with BytesIO instead.
    def get_image_layer(self, image_name: ImageName, layer: FormattedSHA256):
        """
        Retrieves a single image layer.

        Args:
            image_name: Name of the image under which the layer exists.
            layer: The layer identifier in the form: <hash type>:<digest value>.

        Returns:
            TODO
        """
        headers = self._get_request_headers(
            image_name, {"Accept": RegistryV2ImageSource.BLOB_MIME_TYPE}
        )
        url = RegistryV2ImageSource.BLOB_URL_PATTERN.format(
            image_name.resolve_endpoint(), image_name.resolve_image(), layer
        )
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.content

    # ImageSource Members

    def get_image_config(self, image_name: ImageName) -> ImageConfig:
        config_digest = self.get_manifest(image_name).get_config_digest()
        return ImageConfig(self.get_image_layer(image_name, config_digest))

    def get_image_layer_to_disk(self, image_name: ImageName, layer: str, file):
        headers = self._get_request_headers(
            image_name, {"Accept": RegistryV2ImageSource.BLOB_MIME_TYPE}
        )
        url = RegistryV2ImageSource.BLOB_URL_PATTERN.format(
            image_name.resolve_endpoint(), image_name.resolve_image(), layer
        )
        response = requests.get(url, headers=headers, stream=True)

        size = 0
        hasher = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=RegistryV2ImageSource.CHUNK_SIZE):
            if not chunk:
                break
            file.write(chunk)
            size += len(chunk)
            hasher.update(chunk)
        file.flush()
        os.fsync(file.fileno())

        # Be kind, rewind ...
        file.seek(0)

        return {"digest": FormattedSHA256(hasher.hexdigest()), "size": size}

    def get_manifest(self, image_name: ImageName = None) -> Manifest:
        headers = self._get_request_headers(
            image_name, {"Accept": RegistryV2ImageSource.MANIFEST_MIME_TYPE}
        )
        url = RegistryV2ImageSource.MANIFEST_URL_PATTERN.format(
            image_name.resolve_endpoint(), image_name.resolve_image(), image_name.tag
        )

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        raw_registry_manifest = response.content

        return RegistryV2Manifest(raw_registry_manifest)

    def put_image_config(self, image_name: ImageName, image_config: ImageConfig):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_config")
            return
        if not self.layer_exists(image_name, image_config.get_config_digest()):
            self.put_image_layer(image_name, image_config.get_config())

    def put_image_layer(self, image_name: ImageName, content):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer")
            return

        digest = formatted_digest(content)

        # TODO: Why doesn't this work?
        # return self.monolithic_blob_upload(image_name, content, digest)

        location = self.initiate_resumable_blob_upload(image_name).headers["location"]
        return self.complete_resumable_blob_upload(location, digest, content)

    def put_image_layer_from_disk(self, image_name: ImageName, file):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer_from_disk")
            return
        location = self.initiate_resumable_blob_upload(image_name).headers["location"]
        offset = 0
        hasher = hashlib.sha256()
        while True:
            chunk = file.read(RegistryV2ImageSource.CHUNK_SIZE)
            if not chunk:
                break
            location = self.resume_blob_upload(location, offset, chunk).headers[
                "location"
            ]
            offset += len(chunk)
            hasher.update(chunk)
        digest = FormattedSHA256(hasher.hexdigest())

        return self.complete_resumable_blob_upload(location, digest)

    def put_manifest(self, manifest: Manifest, image_name: ImageName = None):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_manifest")
            return
        url = RegistryV2ImageSource.MANIFEST_URL_PATTERN.format(
            image_name.resolve_endpoint(), image_name.resolve_image(), image_name.tag
        )
        headers = self._get_request_headers(
            image_name, {"Content-Type": RegistryV2ImageSource.MANIFEST_MIME_TYPE}
        )

        response = requests.put(
            url, headers=headers, data=str(manifest).encode("utf-8")
        )
        must_be_equal(201, response.status_code, "Failed to upload manifest")

        return response

    def layer_exists(self, image_name: ImageName, layer: FormattedSHA256) -> bool:
        url = RegistryV2ImageSource.BLOB_URL_PATTERN.format(
            image_name.resolve_endpoint(), image_name.resolve_image(), layer
        )
        headers = self._get_request_headers(image_name)
        response = requests.head(url, headers=headers)

        return response.status_code in [200, 307]

    def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source: ImageSource,
        dest_image_name: ImageName,
    ):
        LOGGER.debug("Signing: %s ...", src_image_name)

        # Generate a signed image configuration ...
        data = self._sign_image_config(signer, src_image_name)
        manifest = data["verify_image_data"]["manifest"]
        LOGGER.debug("    Signature:\n%s", data["signature_value"])
        image_config = data["image_config"]

        # Replicate all of the image layers ...
        registry_layers = manifest.get_layers()
        registry_layers_changed = registry_layers.copy()
        for i, registry_layer in enumerate(registry_layers):
            if not dest_image_source.layer_exists(dest_image_name, registry_layer):
                digest = dest_image_source.put_image_layer_from_disk(
                    dest_image_name,
                    data["verify_image_data"]["compressed_layer_files"][i],
                )
                registry_layers_changed[i] = digest
        registry_layers = registry_layers_changed

        # Push the new image configuration ...
        config_digest_signed = image_config.get_config_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest_signed)
        dest_image_source.put_image_config(dest_image_name, image_config)

        # Generate a new registry manifest, and push ...
        if isinstance(dest_image_source, ArchiveImageSource):
            raise NotImplementedError
        elif isinstance(dest_image_source, RegistryV2ImageSource):
            manifest_signed = copy.deepcopy(manifest)  # type: RegistryV2Manifest
            manifest_signed.set_config_digest(
                config_digest_signed, len(image_config.get_config())
            )
            manifest_signed.set_layers(registry_layers)
            data["manifest_signed"] = manifest_signed
            dest_image_source.put_manifest(manifest_signed, dest_image_name)
        elif isinstance(dest_image_source, DeviceMapperRepositoryImageSource):
            raise NotImplementedError
        else:
            raise RuntimeError(
                "Unknown derived class: {0}".format(type(dest_image_source))
            )

        LOGGER.debug("Created new image: %s", dest_image_name)

        return data

    def unsign_image(
        self, src_image_name: ImageName, dest_image_source, dest_image_name: ImageName
    ):
        LOGGER.debug("Unsigning: %s ...", src_image_name)

        # Generate an unsigned image configuration ...
        data = self._unsign_image_config(src_image_name)
        manifest = data["verify_image_data"]["manifest"]
        image_config = data["image_config"]

        # Replicate all of the image layers ...
        registry_layers = manifest.get_layers()
        for i, registry_layer in enumerate(registry_layers):
            if not dest_image_source.layer_exists(dest_image_name, registry_layer):
                dest_image_source.put_image_layer_from_disk(
                    dest_image_name,
                    data["verify_image_data"]["compressed_layer_files"][i],
                )

        # Push the new image configuration ...
        config_digest_unsigned = image_config.get_config_digest()
        LOGGER.debug("    config digest (unsigned): %s", config_digest_unsigned)
        dest_image_source.put_image_config(dest_image_name, image_config)

        # Generate a new registry manifest, and push ...
        if isinstance(dest_image_source, ArchiveImageSource):
            raise NotImplementedError
        elif isinstance(dest_image_source, RegistryV2ImageSource):
            manifest_unsigned = copy.deepcopy(manifest)  # type: RegistryV2Manifest
            manifest_unsigned.set_config_digest(
                config_digest_unsigned, len(image_config.get_config())
            )
            data["manifest_unsigned"] = manifest_unsigned
            dest_image_source.put_manifest(manifest_unsigned, dest_image_name)
        elif isinstance(dest_image_source, DeviceMapperRepositoryImageSource):
            raise NotImplementedError
        else:
            raise RuntimeError(
                "Unknown derived class: {0}".format(type(dest_image_source))
            )

        LOGGER.debug("Created new image: %s", dest_image_name)

        return data

    def verify_image_integrity(self, image_name: ImageName):
        data = self._verify_image_config(image_name)

        # Reconcile manifest layers and image layers (in order)...
        compressed_layer_files = []
        uncompressed_layer_files = []
        for i, layer in enumerate(data["manifest_layers"]):
            # Retrieve the registry image layer and verify the digest ...
            compressed_layer_files.append(tempfile.NamedTemporaryFile())
            data_compressed = self.get_image_layer_to_disk(
                image_name, layer, compressed_layer_files[i]
            )
            must_be_equal(
                layer,
                data_compressed["digest"],
                "Registry layer[{0}] digest mismatch".format(i),
            )

            # Decompress (convert) the registry image layer into the image layer
            # and verify the digest ...
            uncompressed_layer_files.append(tempfile.NamedTemporaryFile())
            data_uncompressed = gunzip(
                compressed_layer_files[i], uncompressed_layer_files[i]
            )
            must_be_equal(
                data["image_layers"][i],
                data_uncompressed["digest"],
                "Image layer[{0}] digest mismatch".format(i),
            )

        LOGGER.debug("Integrity check passed.")

        return {
            "compressed_layer_files": compressed_layer_files,
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": uncompressed_layer_files,
        }


class DeviceMapperRepositoryImageSource(ImageSource):
    """
    Docker repository image source.
    """

    DOCKER_ROOT = Path("/var/lib/docker")
    DM_CONTENT_ROOT = DOCKER_ROOT.joinpath("image/devicemapper/imagedb/content/sha256")
    DM_LAYER_ROOT = DOCKER_ROOT.joinpath("image/devicemapper/layerdb/sha256")
    DM_METADATA_ROOT = DOCKER_ROOT.joinpath("devicemapper/metadata")
    DM_REPOSITORIES = DOCKER_ROOT.joinpath("image/devicemapper/repositories.json")

    CHUNK_SIZE = 4096

    def __init__(self, **kwargs):
        super(DeviceMapperRepositoryImageSource, self).__init__(**kwargs)

    # ImageSource Members

    def get_image_config(self, image_name: ImageName) -> ImageConfig:
        config_digest = self.get_manifest().get_config_digest(image_name)
        path = DeviceMapperRepositoryImageSource.DM_CONTENT_ROOT.joinpath(
            config_digest.sha256
        )
        raw_image_config = read_file(path)
        return ImageConfig(raw_image_config)

    def get_image_layer_to_disk(self, image_name: ImageName, layer: str, file):
        # Retrieve the devicemapper metadata ...
        path = DeviceMapperRepositoryImageSource.DM_LAYER_ROOT.joinpath(
            layer[7:], "cache-id"
        )
        cache_id = read_file(path).decode("utf-8")
        if not cache_id:
            raise RuntimeError("Unable to find cache id for layer: {0}".format(layer))
        path = DeviceMapperRepositoryImageSource.DM_METADATA_ROOT.joinpath(cache_id)
        raw_metadata = read_file(path)
        metadata = json.loads(raw_metadata)
        if not (metadata["device_id"] or metadata["size"]):
            raise RuntimeError(
                "Unable to find device id and / or size for layer: {0}".format(layer)
            )

        # Create the devicemapper table ...
        device_name = "dsv-{0}".format(layer)
        # TODO: How to we find the vgname?
        volume_group = "/dev/mapper/rhel-docker--pool"
        table = "0 {0} thin {1} {2}".format(
            metadata["size"], volume_group, metadata["device_id"]
        )
        subprocess.run(
            ["/sbin/dmsetup", "create", device_name, "--table", table], check=True
        )

        # Mount the layer ...
        mount = Path(tempfile.mkdtemp())
        subprocess.run(
            [
                "mount",
                "-o",
                "ro",
                Path("/dev/mapper").joinpath(device_name),
                mount.absolute(),
            ],
            check=True,
        )

        # Reconstruct the layer tar ...
        path = DeviceMapperRepositoryImageSource.DM_LAYER_ROOT.joinpath(
            layer[7:], "tar-split.json.gz"
        )
        rootfs = mount.joinpath("rootfs")
        if not rootfs.exists():
            raise RuntimeError(
                "Root filesystem does not exist for layer: {0}".format(layer)
            )
        # TODO: Replace this with a pure-python implementation
        process = subprocess.Popen(
            ["tar-split", "asm", "--input", str(path), "--path", rootfs],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        # TODO: This still buffers the entire file in memory ...
        result = copy_file(process.stdout, file)
        return_code = process.wait(120)
        if return_code != 0:
            raise RuntimeError("Tar-split failed!")

        # Unmount the layer, remove the devicemapper table, delete the mountpoint ...
        subprocess.run(["umount", mount.absolute()], check=True)
        subprocess.run(["/sbin/dmsetup", "remove", device_name], check=True)
        mount.rmdir()

        return result

    def get_manifest(self, image_name: ImageName = None) -> Manifest:
        raw_repository_manifest = read_file(
            DeviceMapperRepositoryImageSource.DM_REPOSITORIES
        )
        return DeviceMapperRepositoryManifest(raw_repository_manifest)

    def put_image_config(self, image_name: ImageName, image_config: ImageConfig):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_config")
            return
        # TODO: Remove debug code
        # path = DeviceMapperRepositoryImageSource.DM_CONTENT_ROOT.joinpath(image_config.get_config_digest().sha256)
        path = Path(
            "/tmp/docker-ridavis/image/devicemapper/imagedb/conent/sha256/"
        ).joinpath(image_config.get_config_digest().sha256)
        path.parent.mkdir(exist_ok=True, parents=True)
        write_file(path, image_config.get_config())

    def put_image_layer(self, image_name: ImageName, content):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer")
            return
        # TODO: Implement this method ...
        raise NotImplementedError

    def put_image_layer_from_disk(self, image_name: ImageName, file):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_image_layer_from_disk")
            return
        # TODO: Implement this method ...
        raise NotImplementedError

    def put_manifest(self, manifest: Manifest, image_name: ImageName = None):
        if self.dry_run:
            LOGGER.debug("Dry Run: skipping put_manifest")
            return
        # TODO: Remove debug code
        # path = DeviceMapperRepositoryImageSource.DM_REPOSITORIES
        path = Path("/tmp/docker-ridavis/repositories.json")
        path.parent.mkdir(exist_ok=True, parents=True)
        write_file(path, str(manifest).encode("utf-8"))

    def layer_exists(self, image_name: ImageName, layer: FormattedSHA256) -> bool:
        result = False
        path_layer = DeviceMapperRepositoryImageSource.DM_LAYER_ROOT.joinpath(
            layer.sha256
        ).joinpath("cache-id")
        if path_layer.exists():
            cache_id = read_file(path_layer).decode("utf-8")
            path_cache = DeviceMapperRepositoryImageSource.DM_METADATA_ROOT.joinpath(
                cache_id
            )
            result = path_cache.exists()
        return result

    def sign_image(
        self,
        signer: Signer,
        src_image_name: ImageName,
        dest_image_source: ImageSource,
        dest_image_name: ImageName,
    ):
        LOGGER.debug("Signing: %s ...", src_image_name)

        # Generate a signed image configuration ...
        data = self._sign_image_config(signer, src_image_name)
        manifest = data["verify_image_data"]["manifest"]
        LOGGER.debug("    Signature:\n%s", data["signature_value"])
        image_config = data["image_config"]

        # Replicate all of the image layers ...
        repository_layers = manifest.get_layers(src_image_name)
        for i, repository_layer in enumerate(repository_layers):
            if not dest_image_source.layer_exists(dest_image_name, repository_layer):
                dest_image_source.put_image_layer_from_disk(
                    dest_image_name,
                    data["verify_image_data"]["compressed_layer_files"][i],
                )
        # TODO: We we need to track the layer translations here? Is this possible for DM repos?

        # Push the new image configuration ...
        config_digest_signed = image_config.get_config_digest()
        LOGGER.debug("    config digest (signed): %s", config_digest_signed)
        dest_image_source.put_image_config(dest_image_name, image_config)

        # Generate a new repository manifest, and push ...
        if isinstance(dest_image_source, ArchiveImageSource):
            raise NotImplementedError
        elif isinstance(dest_image_source, RegistryV2ImageSource):
            raise NotImplementedError
        elif isinstance(dest_image_source, DeviceMapperRepositoryImageSource):
            manifest_signed = (
                dest_image_source.get_manifest()
            )  # type: DeviceMapperRepositoryManifest

            if dest_image_name.tag:
                manifest_signed.override_config(config_digest_signed, dest_image_name)
            data["manifest_signed"] = manifest_signed
            dest_image_source.put_manifest(manifest_signed, dest_image_name)
        else:
            raise RuntimeError(
                "Unknown derived class: {0}".format(type(dest_image_source))
            )

        LOGGER.debug("Created new image: %s", dest_image_name)

        return data

    def unsign_image(
        self, src_image_name: ImageName, dest_image_source, dest_image_name: ImageName
    ):
        raise NotImplementedError

    def verify_image_integrity(self, image_name: ImageName):
        data = self._verify_image_config(image_name)

        # Note: We do not need to reconcile manifest layer ids here, as "we" derived them in
        # :func:docker_sign_verify.manifests.DeviceMapperRepositoryManifest.get_layers.

        # Reconcile manifest layers and image layers (in order)...
        uncompressed_layer_files = []
        for i, layer in enumerate(data["manifest_layers"]):
            # Retrieve the repository image layer and verify the digest ...
            uncompressed_layer_files.append(tempfile.NamedTemporaryFile())
            data_compressed = self.get_image_layer_to_disk(
                image_name, layer, uncompressed_layer_files[i]
            )
            must_be_equal(
                data["image_layers"][i],
                data_compressed["digest"],
                "Repository layer[{0}] digest mismatch".format(i),
            )

        LOGGER.debug("Integrity check passed.")

        return {
            "image_config": data["image_config"],
            "manifest": data["manifest"],
            "uncompressed_layer_files": uncompressed_layer_files,
        }
