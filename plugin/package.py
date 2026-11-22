"""Build a portable plugin archive for one running instance."""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZipFile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("base", help="Public HTTPS base URL, including any path prefix")
parser.add_argument("output", type=Path)
parser.add_argument("--name", help="Distinct plugin and connector name when installing alongside another Ping")
args = parser.parse_args()
if args.name is not None and not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.name):
    parser.error("use lowercase letters, digits and hyphens for --name")
base = args.base.rstrip("/")
url = urlsplit(base)
if url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment:
    parser.error("use the public HTTPS base URL of the instance")
root = Path(__file__).resolve().parent
manifest = json.loads((root / "plugin.json").read_text())
manifest["homepage"] = base + "/"
servers = json.loads((root / "mcp.json").read_text())
server = servers["mcpServers"].pop("ping-their-ai")
source_url = server["url"]
server["url"] = base + "/mcp"
if args.name:
    manifest["name"] = args.name
    manifest["extensions"]["com.openai"]["interface"]["displayName"] = args.name
servers["mcpServers"][manifest["name"]] = server
with ZipFile(args.output, "w", ZIP_DEFLATED) as archive:
    for name, data in (("plugin.json", manifest), ("mcp.json", servers)):
        archive.writestr(name, json.dumps(data, indent=2) + "\n")
    archive.write(root.parent / "LICENSE", "LICENSE")
    archive.write(root / "assets/ping.png", "assets/ping.png")
    for skill in sorted((root / "skills").rglob("SKILL.md")):
        archive.writestr(str(skill.relative_to(root)), skill.read_text().replace(source_url, server["url"]))
