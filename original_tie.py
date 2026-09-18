"""Deterministic ZIP/XBRL comparison, independent of the acquisition route."""
from html.parser import HTMLParser
import io
import re
import zipfile
from xml.etree import ElementTree

from evidence_core import ContractError
from source_acquisition import gate, sha256


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def normalized(text):
    parser = Text()
    parser.feed(text)
    return re.sub(r"\s+", "", " ".join(parser.parts))


def compare_zip(data, row, artifact):
    if artifact["doc_id"] != row["doc_id"]:
        return gate("original_document_mismatch")
    if sha256(data) != artifact["byte_sha256"] or len(data) != artifact["byte_count"]:
        raise ContractError("original_byte_integrity_failure")
    candidate = normalized(row["text"])
    if not candidate:
        return gate("empty_normalized_text")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(i.file_size for i in archive.infolist()) > 32 * 1024 * 1024:
                return gate("original_expansion_limit")
            matches, members = [], []
            for info in archive.infolist():
                if not info.filename.lower().endswith(".xbrl"):
                    continue
                xml = archive.read(info)
                members.append(info.filename)
                # Also detect declarations in UTF-16/32 before invoking Expat.
                declarations = xml.replace(b"\x00", b"").upper()
                if b"<!DOCTYPE" in declarations:
                    return gate("xml_doctype_rejected")
                if b"<!ENTITY" in declarations:
                    return gate("xml_entity_rejected")
                for position, element in enumerate(ElementTree.fromstring(xml).iter()):
                    if element.tag.rsplit("}", 1)[-1] == row["tag"]:
                        original = "".join(element.itertext())
                        original_normalized = normalized(original)
                        if original_normalized == candidate:
                            matches.append({"member": info.filename, "tag": element.tag,
                                "element_index": position, "context_ref": element.get("contextRef"),
                                "member_sha256": sha256(xml),
                                "original_text_sha256": sha256(original.encode("utf-8")),
                                "original_normalized_text_sha256": sha256(original_normalized.encode("utf-8"))})
            if not matches:
                return gate("original_tag_text_not_matched")
            return gate(original_sha256=artifact["byte_sha256"], original_byte_count=len(data),
                doc_id=row["doc_id"], locators=matches, method="xbrl_tag_normalized_text_exact_v1",
                original_schema_profile={"format": "zip/xbrl", "xbrl_members": members},
                numad_text_sha256=sha256(row["text"].encode("utf-8")),
                numad_normalized_text_sha256=sha256(candidate.encode("utf-8")),
                compared_text_sha256=sha256(candidate.encode("utf-8")),
                original_retrieved_at=artifact.get("retrieved_at"),
                original_provider_retrieved_at=artifact.get("original_provider_retrieved_at"))
    except (zipfile.BadZipFile, ElementTree.ParseError, RuntimeError, ValueError):
        return gate("original_parse_failed")
