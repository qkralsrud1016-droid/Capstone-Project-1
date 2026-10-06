"""
File filtering program for Label1, Label2, Label3, and Label4.
"""

import os
import sys
import re
from io import BytesIO

from pypdf import PdfReader
from docx import Document
from PIL import Image
import pytesseract
import pytsk3


# ============================================================
# CONFIGURATION
# ============================================================

def read_config(config_file):
    location = ""
    file_type_line = ""
    keyword_line = ""
    recovery_location = ""

    with open(config_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if key == "location":
                location = os.path.expanduser(value)
            elif key == "filetype":
                file_type_line = value
            elif key in ("contain", "keywords"):
                keyword_line = value
            elif key == "recoverylocation":
                recovery_location = os.path.expanduser(value)

    # 기본 카빙 경로 자동 지정 (설정 파일에 없을 경우)
    if not recovery_location:
        for fallback in ["carve_out", "output_result", "matched_files", "ole", "jpg"]:
            if os.path.exists(fallback):
                recovery_location = fallback
                break

    return location, file_type_line, keyword_line, recovery_location


def parse_file_types(file_type_line):
    return [
        file_type.strip().lower().lstrip(".")
        for file_type in re.split(r"\s+or\s+", file_type_line, flags=re.IGNORECASE)
        if file_type.strip()
    ]


# ============================================================
# TEXT EXTRACTION - RAW & BINARY (DOC / OLE SUPPORT)
# ============================================================

def extract_text_raw_bytes(file_bytes):
    """OLE/DOC 등 구조화된 바이너리 파일에서 읽기 가능한 ASCII/UTF-8 문자열을 추출"""
    return " ".join(
        re.findall(r"[\x20-\x7E]{4,}", file_bytes.decode("latin-1", errors="ignore"))
    ).lower()


def extract_text_pdf_bytes(file_bytes):
    text = ""
    try:
        reader = PdfReader(BytesIO(file_bytes))
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text.lower() + "\n"
    except Exception:
        text = extract_text_raw_bytes(file_bytes)
    return text


def extract_text_txt_bytes(file_bytes):
    return file_bytes.decode("utf-8", errors="ignore").lower()


def extract_text_docx_bytes(file_bytes):
    text = ""
    try:
        document = Document(BytesIO(file_bytes))
        for paragraph in document.paragraphs:
            text += paragraph.text.lower() + "\n"
    except Exception:
        text = extract_text_raw_bytes(file_bytes)
    return text


def extract_text_image_bytes(file_bytes):
    try:
        with Image.open(BytesIO(file_bytes)) as image:
            text = pytesseract.image_to_string(image)
        return text.lower()
    except Exception:
        return extract_text_raw_bytes(file_bytes)


def extract_text_from_bytes(file_bytes, extension):
    extension = extension.lower()

    if extension == "pdf":
        return extract_text_pdf_bytes(file_bytes)
    elif extension == "txt":
        return extract_text_txt_bytes(file_bytes)
    elif extension == "docx":
        return extract_text_docx_bytes(file_bytes)
    elif extension in ("jpg", "jpeg", "png"):
        return extract_text_image_bytes(file_bytes)
    elif extension in ("doc", "ole"):
        return extract_text_raw_bytes(file_bytes)
    
    return extract_text_raw_bytes(file_bytes)


# ============================================================
# KEYWORD MATCHING
# ============================================================

def contains_keyword(text, word):
    text = text.lower()
    word = word.strip().lower()
    if not word:
        return False

    if word.isalpha():
        pattern = r"\b" + re.escape(word) + r"\b"
        return re.search(pattern, text) is not None

    return word in text


def keyword_match(text, keyword_line):
    if text is None:
        return False

    text = text.lower()
    keyword_line = keyword_line.lower()

    or_parts = [part.strip() for part in keyword_line.split(" or ") if part.strip()]

    for part in or_parts:
        if " and " in part:
            and_parts = [word.strip() for word in part.split(" and ") if word.strip()]
            if all(contains_keyword(text, word) for word in and_parts):
                return True
        else:
            if contains_keyword(text, part):
                return True

    return False


# ============================================================
# LABEL4 - RECOVERED/CARVED FILES SCAN
# ============================================================

def process_recovered_fragments(recovery_path, file_types, keyword_line):
    matched_files = []

    for root, _, files in os.walk(recovery_path):
        for file_name in files:
            if file_name.startswith("."):  # .DS_Store 등 제외
                continue

            file_path = os.path.join(root, file_name)
            extension = os.path.splitext(file_name)[1].lower().lstrip(".")

            try:
                with open(file_path, "rb") as f:
                    file_bytes = f.read()

                text = extract_text_from_bytes(file_bytes, extension)

                if text and keyword_match(text, keyword_line):
                    matched_files.append(file_path)

            except Exception:
                pass

    return matched_files


# ============================================================
# LABEL4 - RECURSIVE DD IMAGE SCAN
# ============================================================

def process_dd_directory(file_system, directory, file_types, keyword_line, current_path=""):
    matched_files = []

    for entry in directory:
        try:
            file_name = entry.info.name.name.decode("utf-8", errors="ignore")
        except Exception:
            continue

        if file_name in (".", ".."):
            continue

        metadata = entry.info.meta
        if metadata is None:
            continue

        full_path = f"{current_path}/{file_name}" if current_path else file_name

        # 디렉터리인 경우 재귀 탐색
        if metadata.type == pytsk3.TSK_FS_META_TYPE_DIR:
            try:
                sub_dir = file_system.open_dir(path=full_path)
                matched_files.extend(
                    process_dd_directory(file_system, sub_dir, file_types, keyword_line, full_path)
                )
            except Exception:
                pass

        # 일반 파일인 경우
        elif metadata.type == pytsk3.TSK_FS_META_TYPE_REG:
            extension = os.path.splitext(file_name)[1].lower().lstrip(".")

            if extension in file_types or "doc" in file_types:
                try:
                    file_object = file_system.open_meta(inode=metadata.addr)
                    file_size = metadata.size
                    file_bytes = file_object.read_random(0, file_size)

                    text = extract_text_from_bytes(file_bytes, extension)

                    if text and keyword_match(text, keyword_line):
                        matched_files.append(full_path)

                except Exception:
                    pass

    return matched_files


def process_dd_image(dd_path, file_types, keyword_line):
    try:
        image = pytsk3.Img_Info(dd_path)
        file_system = pytsk3.FS_Info(image)
        root_directory = file_system.open_dir(path="/")
        return process_dd_directory(file_system, root_directory, file_types, keyword_line)
    except Exception as e:
        print(f"TSK File System Load Warning: {e}")
        return []


# ============================================================
# RAW KEYWORD CHECK
# ============================================================

def scan_raw_dd(dd_path, keyword_line):
    found_keywords = []
    with open(dd_path, "rb") as f:
        data = f.read().lower()

    keyword_parts = [kw.strip() for kw in keyword_line.lower().split(" or ") if kw.strip()]

    for keyword in keyword_parts:
        if " and " in keyword:
            continue
        keyword_bytes = keyword.encode("utf-8", errors="ignore")
        if keyword_bytes in data:
            found_keywords.append(keyword)

    return found_keywords


# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test.py <config_file>")
        sys.exit()

    config_file = sys.argv[1]
    if not os.path.isfile(config_file):
        print("Config file not found:", config_file)
        sys.exit()

    location, file_type_line, keyword_line, recovery_location = read_config(config_file)

    if not location or not file_type_line or not keyword_line:
        print("Config file must contain Location, FileType, and Contain/Keywords.")
        sys.exit()

    file_types = parse_file_types(file_type_line)

    if location.lower().endswith(".dd"):
        if not os.path.isfile(location):
            print("Invalid disk image:", location)
            sys.exit()

        print("Disk image detected:", location)

        # 1. DD 이미지 내 활성 파일 스캔
        matched_files = process_dd_image(location, file_types, keyword_line)

        if matched_files:
            print("\nFollowing matching file(s) found in disk image:")
            for file_name in matched_files:
                print(file_name)
            return

        print("\nNo active matching files found.")

        # 2. 카빙/복구 폴더 스캔
        if recovery_location and os.path.isdir(recovery_location):
            print(f"Checking recovered files in '{recovery_location}'...")
            recovered_matches = process_recovered_fragments(
                recovery_location, file_types, keyword_line
            )

            if recovered_matches:
                print("\nFollowing matching recovered file(s) found:")
                for file_path in recovered_matches:
                    print(file_path)
                return

        # 3. Raw 이미지 키워드 스캔
        raw_matches = scan_raw_dd(location, keyword_line)
        if raw_matches:
            print("\nKeyword(s) found in raw disk image:")
            for keyword in raw_matches:
                print(keyword)

if __name__ == "__main__":
    main()
    
# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test.py <config_file>")
        sys.exit()

    config_file = sys.argv[1]
    if not os.path.isfile(config_file):
        print("Config file not found:", config_file)
        sys.exit()

    location, file_type_line, keyword_line, recovery_location = read_config(config_file)

    if not location or not file_type_line or not keyword_line:
        print("Config file must contain Location, FileType, and Contain/Keywords.")
        sys.exit()

    file_types = parse_file_types(file_type_line)

    # ========================================================
    # LABEL4 (DD 이미지 파일 처리)
    # ========================================================
    if location.lower().endswith(".dd"):
        if not os.path.isfile(location):
            print("Invalid disk image:", location)
            sys.exit()

        matched_files = []

        # 1. DD 이미지 내부 활성 파일 스캔
        matched_files = process_dd_image(location, file_types, keyword_line)

        # 2. 활성 파일이 없고 복구 경로가 존재하는 경우 복구 파일 스캔
        if not matched_files and recovery_location and os.path.isdir(recovery_location):
            recovered = process_recovered_fragments(recovery_location, file_types, keyword_line)
            # Label1 양식처럼 파일 이름만 추출 (경로 제외)
            matched_files = [os.path.basename(f) for f in recovered]

        # Label1과 동일한 양식으로 출력
        if matched_files:
            print(f"Following matching file(s) found in {location}:")
            for file_name in matched_files:
                print(file_name)
        else:
            print(f"No matching file(s) found in {location}.")

    # ========================================================
    # LABEL1 / LABEL2 / LABEL3 (일반 디렉터리 처리)
    # ========================================================
    else:
        if not os.path.isdir(location):
            print("Invalid directory:", location)
            sys.exit()

        matched_files = process_directory(location, file_types, keyword_line)

        if matched_files:
            # Label1처럼 파일명만 출력하도록 지정 (경로 포함 출력을 원할 경우 os.path.basename 제거)
            print(f"Following matching file(s) found in {location}:")
            for file_path in matched_files:
                print(os.path.basename(file_path))
        else:
            print(f"No matching file(s) found in {location}.")


if __name__ == "__main__":
    main()