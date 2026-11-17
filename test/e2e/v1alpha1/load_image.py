#!/usr/bin/env python3
"""Import one image into a Kind node as a single linux/amd64 image.

docker save of a multi-arch index references an arm64 manifest that is not in
the tar. containerd then refuses the import. This rewrites the OCI index so the
name points at the amd64 manifest and imports that.
"""

import io
import json
import subprocess
import sys
import tarfile


def full_name(image: str) -> str:
    if image.startswith("localhost/") or image.startswith("docker.io/"):
        return image
    if "/" not in image:
        return "docker.io/library/" + image
    first, _, _ = image.partition("/")
    if "." in first or ":" in first or first == "localhost":
        return image
    return "docker.io/" + image


def main() -> None:
    image, cluster = sys.argv[1], sys.argv[2]
    raw = subprocess.check_output(["docker", "save", image])
    src = tarfile.open(fileobj=io.BytesIO(raw))
    names = set(src.getnames())
    out = io.BytesIO()
    if "index.json" in names:
        index = json.loads(src.extractfile("index.json").read())

        def read_blob(digest: str) -> dict:
            path = "blobs/sha256/" + digest.split(":", 1)[1]
            return json.loads(src.extractfile(path).read())

        chosen = index["manifests"][0]
        doc = read_blob(chosen["digest"])
        if "manifests" in doc and "layers" not in doc:
            amd = next(
                (
                    m
                    for m in doc["manifests"]
                    if (m.get("platform") or {}).get("os") == "linux"
                    and (m.get("platform") or {}).get("architecture") == "amd64"
                ),
                doc["manifests"][0],
            )
            ann = dict(chosen.get("annotations") or {})
            ann["io.containerd.image.name"] = full_name(image)
            ann["org.opencontainers.image.ref.name"] = full_name(image)
            amd = dict(amd)
            amd["annotations"] = ann
            index["manifests"] = [amd]
        payload = json.dumps(index).encode()
        with tarfile.open(fileobj=out, mode="w") as dst:
            for member in src.getmembers():
                if member.name == "index.json":
                    info = tarfile.TarInfo(name="index.json")
                    info.size = len(payload)
                    info.mode = member.mode
                    dst.addfile(info, io.BytesIO(payload))
                elif member.isfile():
                    dst.addfile(member, src.extractfile(member))
                else:
                    dst.addfile(member)
    else:
        out.write(raw)

    node = f"{cluster}-control-plane"
    proc = subprocess.run(
        ["docker", "exec", "-i", node, "ctr", "-n", "k8s.io", "images", "import", "-"],
        input=out.getvalue(),
    )
    if proc.returncode != 0:
        sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
