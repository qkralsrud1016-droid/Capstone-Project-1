import os

import sys

import re

import json

from io import BytesIO

import ollama

from pypdf import PdfReader

from docx import Document

from PIL import Image

import pytesseract

# ============================================================

# MODEL CONFIGURATION

# ============================================================

TEXT_MODEL = "qwen3:4b-instruct"

VISION_MODEL = "qwen2.5vl:3b"

IMAGE_EXTENSIONS = (

    "jpg",

    "jpeg",

    "png",

    "gif"

)

# ============================================================

# CONFIGURATION

# ============================================================

def read_config(config_file):

    """

    Read the Capstone 2 configuration file.

    Expected format:

    Location: sample.dd

    RecoveryLocation: carve_out

    """

    location = ""

    recovery_location = ""

    with open(

        config_file,

        "r",

        encoding="utf-8"

    ) as f:

        for line in f:

            line = line.strip()

            if not line or ":" not in line:

                continue

            key, value = line.split(

                ":",

                1

            )

            key = key.strip().lower()

            value = value.strip()

            if key == "location":

                location = os.path.expanduser(

                    value

                )

            elif key == "recoverylocation":

                recovery_location = os.path.expanduser(

                    value

                )

    if not recovery_location:

        for fallback in [

            "carve_out",

            "output_result",

            "matched_files"

        ]:

            if os.path.isdir(

                fallback

            ):

                recovery_location = fallback

                break

    return (

        location,

        recovery_location

    )

# ============================================================

# LLM QUESTION INTERPRETATION

# ============================================================

def interpret_question(question):

    """

    Interpret the investigator's natural-language question.

    The LLM converts the question into structured filtering

    criteria.

    Abstract technical concepts may be normalized into concise

    evidence-oriented terminology.

    Broad semantic categories are preserved.

    """

    prompt = f"""

You are assisting a digital forensic investigation.

Interpret the investigator's question and convert it into practical

search criteria for digital evidence.

Rules:

1. Use only the minimum number of search concepts necessary.

2. Do not invent additional investigative topics or context.

3. Preserve the logical relationship between concepts.

4. For a specific concept, use a concise representative search term.

5. If the investigator uses an abstract or descriptive TECHNICAL concept,

   normalize it into the concise technical term that is most likely to

   appear directly in digital evidence.

   Examples:

   "external storage device" -> "USB"

   "removable storage device" -> "USB"

   "USB storage device" -> "USB"

6. Perform this normalization based on meaning, not only exact wording.

7. However, if the investigator intentionally asks about a BROAD SEMANTIC

   CATEGORY, preserve that broad category.

   Examples:

   "animals" -> "animal"

   "animal-related information" -> "animal"

   Do NOT convert "animal" into a fixed list such as

   "dog", "cat", "horse", or other guessed examples.

8. Do not assume that the investigator already knows the specific member

   of a broad category contained in the evidence.

9. Return terms that can be used for evidence filtering.

10. Determine whether multiple search concepts require AND or OR logic.

Return ONLY valid JSON in exactly this format:

{{

    "keywords": ["keyword1", "keyword2"],

    "logic": "AND"

}}

The value of "logic" must be either "AND" or "OR".

Investigator's question:

{question}

"""

    response = ollama.chat(

        model=TEXT_MODEL,

        messages=[

            {

                "role": "user",

                "content": prompt

            }

        ]

    )

    llm_output = (

        response["message"]["content"]

        .strip()

    )

    # Remove possible Markdown JSON fences.

    llm_output = (

        llm_output

        .replace("```json", "")

        .replace("```", "")

        .strip()

    )

    print(

        "\nLLM interpretation:"

    )

    print(

        llm_output

    )

    try:

        criteria = json.loads(

            llm_output

        )

    except json.JSONDecodeError:

        print(

            "\nError: LLM did not return valid JSON."

        )

        sys.exit()

    keywords = criteria.get(

        "keywords",

        []

    )

    logic = criteria.get(

        "logic",

        "AND"

    ).upper()

    if not keywords:

        print(

            "\nError: No keywords were generated."

        )

        sys.exit()

    if logic == "AND":

        keyword_line = " and ".join(

            keywords

        )

    elif logic == "OR":

        keyword_line = " or ".join(

            keywords

        )

    else:

        print(

            "\nError: Unsupported logic:",

            logic

        )

        sys.exit()

    return (

        keyword_line,

        keywords,

        logic

    )

# ============================================================

# TEXT EXTRACTION

# ============================================================

def extract_text_raw_bytes(file_bytes):

    """

    Extract readable ASCII-like strings from binary files,

    including legacy DOC/OLE files.

    """

    decoded = file_bytes.decode(

        "latin-1",

        errors="ignore"

    )

    strings = re.findall(

        r"[\x20-\x7E]{4,}",

        decoded

    )

    return " ".join(

        strings

    ).lower()

def extract_text_pdf_bytes(file_bytes):

    """

    Extract text from PDF files.

    """

    text = ""

    try:

        reader = PdfReader(

            BytesIO(file_bytes)

        )

        for page in reader.pages:

            page_text = (

                page.extract_text()

            )

            if page_text:

                text += (

                    page_text.lower()

                    + "\n"

                )

    except Exception:

        text = extract_text_raw_bytes(

            file_bytes

        )

    return text

def extract_text_txt_bytes(file_bytes):

    """

    Extract text from TXT files.

    """

    return file_bytes.decode(

        "utf-8",

        errors="ignore"

    ).lower()

def extract_text_docx_bytes(file_bytes):

    """

    Extract text from DOCX files.

    """

    text = ""

    try:

        document = Document(

            BytesIO(file_bytes)

        )

        for paragraph in document.paragraphs:

            text += (

                paragraph.text.lower()

                + "\n"

            )

    except Exception:

        text = extract_text_raw_bytes(

            file_bytes

        )

    return text

def extract_ocr_from_image(file_bytes):

    """

    Extract written text appearing inside an image.

    OCR is separate from visual analysis.

    """

    try:

        with Image.open(

            BytesIO(file_bytes)

        ) as image:

            text = (

                pytesseract.image_to_string(

                    image

                )

            )

        return text.lower()

    except Exception:

        return ""

def extract_text_from_bytes(

    file_bytes,

    extension

):

    """

    Select text extraction method according to file type.

    """

    extension = extension.lower()

    if extension == "pdf":

        return extract_text_pdf_bytes(

            file_bytes

        )

    elif extension == "txt":

        return extract_text_txt_bytes(

            file_bytes

        )

    elif extension == "docx":

        return extract_text_docx_bytes(

            file_bytes

        )

    elif extension in IMAGE_EXTENSIONS:

        return extract_ocr_from_image(

            file_bytes

        )

    elif extension in (

        "doc",

        "ole"

    ):

        return extract_text_raw_bytes(

            file_bytes

        )

    return extract_text_raw_bytes(

        file_bytes

    )

# ============================================================

# FILTERING CRITERIA MATCHING

# ============================================================

def contains_keyword(

    text,

    word

):

    """

    Check whether one interpreted search concept exists

    in extracted text.

    Alphabetic terms use whole-word matching.

    """

    text = text.lower()

    word = (

        word.strip()

        .lower()

    )

    if not word:

        return False

    if word.isalpha():

        pattern = (

            r"\b"

            + re.escape(word)

            + r"\b"

        )

        return (

            re.search(

                pattern,

                text

            )

            is not None

        )

    return word in text

def keyword_match(

    text,

    keyword_line

):

    """

    Apply AND / OR filtering criteria to textual evidence.

    """

    if text is None:

        return False

    text = text.lower()

    keyword_line = (

        keyword_line.lower()

    )

    or_parts = [

        part.strip()

        for part

        in keyword_line.split(" or ")

        if part.strip()

    ]

    for part in or_parts:

        if " and " in part:

            and_parts = [

                word.strip()

                for word

                in part.split(" and ")

                if word.strip()

            ]

            if all(

                contains_keyword(

                    text,

                    word

                )

                for word

                in and_parts

            ):

                return True

        else:

            if contains_keyword(

                text,

                part

            ):

                return True

    return False

# ============================================================

# BROAD CATEGORY DETECTION

# ============================================================

def is_animal_query(keywords):

    """

    Determine whether the interpreted question contains

    the broad semantic category 'animal'.

    """

    for keyword in keywords:

        normalized = (

            str(keyword)

            .strip()

            .lower()

        )

        if normalized in (

            "animal",

            "animals"

        ):

            return True

    return False

# ============================================================

# DOCUMENT CONCEPT MATCHING

# ============================================================

def analyze_text_concepts(text, keywords):
    """
    Match extracted document text against the investigation concepts.

    Direct textual matches are accepted first. If a concept is not
    written literally, Qwen3 is used only for the remaining concepts
    so that broader semantic concepts can still be recognised.

    Example:
        investigation concept: "animal"
        document text: "rhino ... USB"
        semantic match: "animal"
    """

    if not text:
        return []

    matched_concepts = []
    unmatched_concepts = []

    # --------------------------------------------------------
    # DIRECT TEXT MATCHING
    # --------------------------------------------------------

    for keyword in keywords:

        keyword_string = str(keyword).strip()

        if not keyword_string:
            continue

        if contains_keyword(
            text,
            keyword_string
        ):

            matched_concepts.append(
                keyword_string
            )

        else:

            unmatched_concepts.append(
                keyword_string
            )

    # If every concept was found directly, no semantic call is needed.
    if not unmatched_concepts:
        return matched_concepts

    # --------------------------------------------------------
    # SEMANTIC MATCHING FOR UNMATCHED CONCEPTS
    # --------------------------------------------------------

    concepts_json = json.dumps(
        unmatched_concepts,
        ensure_ascii=False
    )

    # Limit the text sent to the local model while keeping enough
    # recovered content for the small prototype dataset.
    evidence_text = text[:12000]

    prompt = f"""
You are assisting a digital forensic investigation.

A separate interpretation stage has already produced these predefined
investigation concepts that were NOT matched literally in the recovered
text:

{concepts_json}

Analyze the recovered document text below and determine which of these
PREDEFINED concepts are represented by meaning.

Important rules:

1. Match by semantic meaning, not only exact wording.

2. Do not invent new investigation concepts.

3. Return only concepts from the provided list.

4. A broad semantic category may be represented by a specific member of
   that category. For example, if the concept is "animal", references to
   a rhinoceros, alligator, crocodile, bird, or another real animal can
   represent the concept "animal".

5. A specific concept must not be broadened without justification. For
   example, "alligator" does not represent "rhino".

6. If none of the provided concepts are represented, return an empty
   list.

Return ONLY valid JSON in exactly this format:

{{
    "matched_concepts": ["concept"]
}}

Recovered document text:
---
{evidence_text}
---
"""

    try:

        response = ollama.chat(
            model=TEXT_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        output = (
            response["message"]["content"]
            .strip()
        )

        output = (
            output
            .replace("```json", "")
            .replace("```", "")
            .strip()
        )

        result = json.loads(
            output
        )

        semantic_matches = result.get(
            "matched_concepts",
            []
        )

        if not isinstance(
            semantic_matches,
            list
        ):
            semantic_matches = []

        allowed = {
            concept.lower(): concept
            for concept in unmatched_concepts
        }

        for concept in semantic_matches:

            normalized = (
                str(concept)
                .strip()
                .lower()
            )

            if (
                normalized in allowed
                and allowed[normalized]
                not in matched_concepts
            ):

                matched_concepts.append(
                    allowed[normalized]
                )

    except Exception as e:

        print(
            "Text semantic analysis warning:",
            e
        )

    return matched_concepts


def document_concepts_satisfy_logic(
    matched_concepts,
    keywords,
    logic
):
    """
    Apply the structured AND/OR relationship to concepts matched
    within one document.

    This allows a document containing "rhino" and "USB" to satisfy
    the broader criteria "animal" AND "USB" once "rhino" has been
    semantically recognised as animal-related information.
    """

    matched = {
        str(concept).strip().lower()
        for concept in matched_concepts
    }

    required = [
        str(keyword).strip().lower()
        for keyword in keywords
        if str(keyword).strip()
    ]

    if not required:
        return False

    if logic.upper() == "OR":
        return any(
            concept in matched
            for concept in required
        )

    # Single-concept questions and AND questions both work here.
    return all(
        concept in matched
        for concept in required
    )


# ============================================================

# VISION ANALYSIS

# ============================================================

def analyze_image(

    image_path,

    keywords,

    animal_query

):

    """

    Analyze visible image content.

    Qwen2.5-VL does not independently define the investigation

    scope.

    The investigation concepts are provided by Qwen3.

    The vision model identifies which of those concepts, if any,

    are visually represented in the image.

    """

    concepts_json = json.dumps(

        keywords,

        ensure_ascii=False

    )

    if animal_query:

        category_instruction = """

The investigation contains the broad semantic category "animal".

For this broad category:

- Any clearly visible real animal belongs to the category "animal".

- The exact species does not need to be known.

- A rhinoceros, alligator, crocodile, bird, or any other real animal

  can therefore match the concept "animal".

"""

    else:

        category_instruction = """

The investigation does NOT contain a broad animal-category request.

Only match an investigation concept when the visible image content

actually corresponds to that concept.

For example:

- If the concept is "rhino", a visible rhinoceros matches "rhino".

- An alligator does NOT match "rhino".

- An unrelated animal does NOT match "rhino".

- Do not mark a concept as matched merely because the image contains

  some type of animal.

"""

    prompt = f"""

You are assisting a digital forensic investigation.

A separate language model has already interpreted the investigator's

question and generated these investigation concepts:

{concepts_json}

Analyze the recovered image provided with this message.

Your task is to identify the visible content and determine which

of the PREDEFINED investigation concepts are visually represented

in the image.

Important matching rule:

Match concepts by MEANING, not only by exact wording.

For example:

- "rhino" and "rhinoceros" represent the same concept.

- A visible rhinoceros MUST therefore match the concept "rhino".

- A visible alligator does NOT match "rhino".

- Do not require the exact investigation word to appear in the image.

- Do not add concepts that were not provided.

For broad category concepts:

- If the provided concept is "animal", any clearly visible real animal

  matches the concept "animal".

- The exact animal species does not need to be known.

Tasks:

1. Determine whether a real animal is visibly present.

2. If an animal is visible, identify it when reasonably possible.

3. Briefly describe the main visible content.

4. Compare the visible content with each provided investigation concept

   based on semantic meaning.

5. Return EVERY provided concept that is represented by the image

   in "matched_concepts".

6. If none of the provided concepts are represented,

   return an empty list.

Return ONLY valid JSON in exactly this format:

{{

    "contains_animal": true,

    "animal": "animal name or broader identification",

    "description": "brief factual description",

    "matched_concepts": ["concept"]

}}

"""

    try:

        response = ollama.chat(

            model=VISION_MODEL,

            messages=[

                {

                    "role": "user",

                    "content": prompt,

                    "images": [

                        image_path

                    ]

                }

            ]

        )

        output = (

            response["message"]["content"]

            .strip()

        )

        output = (

            output

            .replace("```json", "")

            .replace("```", "")

            .strip()

        )

        result = json.loads(

            output

        )

        # ----------------------------------------------------

        # CONTAINS ANIMAL

        # ----------------------------------------------------

        contains_animal_value = (

            result.get(

                "contains_animal",

                False

            )

        )

        if isinstance(

            contains_animal_value,

            bool

        ):

            contains_animal = (

                contains_animal_value

            )

        elif isinstance(

            contains_animal_value,

            str

        ):

            contains_animal = (

                contains_animal_value

                .strip()

                .lower()

                == "true"

            )

        else:

            contains_animal = False

        # ----------------------------------------------------

        # ANIMAL IDENTIFICATION

        # ----------------------------------------------------

        animal = (

            str(

                result.get(

                    "animal",

                    ""

                )

            )

            .strip()

        )

        # ----------------------------------------------------

        # DESCRIPTION

        # ----------------------------------------------------

        description = (

            str(

                result.get(

                    "description",

                    ""

                )

            )

            .strip()

        )

        # ----------------------------------------------------

        # MATCHED CONCEPTS

        # ----------------------------------------------------

        matched_concepts = result.get(

            "matched_concepts",

            []

        )

        if not isinstance(

            matched_concepts,

            list

        ):

            matched_concepts = []

        normalized_keywords = {

            str(keyword).strip().lower()

            for keyword in keywords

        }

        validated_matches = []

        for concept in matched_concepts:

            concept_string = (

                str(concept)

                .strip()

            )

            if (

                concept_string.lower()

                in normalized_keywords

            ):

                validated_matches.append(

                    concept_string

                )

        # ----------------------------------------------------

        # BROAD ANIMAL SAFETY RULE

        # ----------------------------------------------------

        #

        # For Q3-style broad animal queries, visible animal

        # presence itself is sufficient to match "animal".

        #

        # This prevents uncertain species identification from

        # causing false negatives.

        # ----------------------------------------------------

        if (

            animal_query

            and contains_animal

            and "animal"

            in normalized_keywords

        ):

            if not any(

                str(match).lower()

                == "animal"

                for match

                in validated_matches

            ):

                validated_matches.append(

                    "animal"

                )

        return {

            "contains_animal": contains_animal,

            "animal": animal,

            "description": description,

            "matched_concepts": validated_matches

        }

    except Exception as e:

        print(

            f"Vision warning for "

            f"{image_path}: {e}"

        )

        return {

            "contains_animal": False,

            "animal": "",

            "description": "",

            "matched_concepts": []

        }

# ============================================================

# IMAGE EVIDENCE PROCESSING

# ============================================================

def process_image_evidence(

    file_path,

    file_bytes,

    keyword_line,

    keywords,

    animal_query

):

    """

    Process recovered image evidence.

    OCR checks written text.

    Qwen2.5-VL checks whether the predefined investigation

    concepts are represented visually.

    An image is relevant when either:

    1. OCR satisfies the textual filtering condition; or

    2. At least one investigation concept is visually matched.

    For a broad animal query, any visible real animal is

    considered relevant.

    """

    # --------------------------------------------------------

    # OCR

    # --------------------------------------------------------

    ocr_text = extract_ocr_from_image(

        file_bytes

    )

    ocr_relevant = False

    if (

        ocr_text

        and keyword_match(

            ocr_text,

            keyword_line

        )

    ):

        ocr_relevant = True

    # --------------------------------------------------------

    # VISION

    # --------------------------------------------------------

    vision_result = analyze_image(

        file_path,

        keywords,

        animal_query

    )

    visual_relevant = bool(

        vision_result[

            "matched_concepts"

        ]

    )

    # --------------------------------------------------------

    # FINAL IMAGE RELEVANCE

    # --------------------------------------------------------

    is_relevant = (

        ocr_relevant

        or visual_relevant

    )

    return (

        is_relevant,

        vision_result,

        "Vision"

    )

# ============================================================

# CAPSTONE 2 - RECOVERED CANDIDATE SCAN

# ============================================================

def process_recovered_candidates(

    recovery_path,

    keyword_line,

    keywords,

    logic,

    question

):

    """

    Scan all recovered candidate evidence.

    Documents:

        text extraction and filtering.

    Images:

        OCR + visual concept analysis.

    """

    matched_files = []

    total_files = 0

    animal_query = is_animal_query(

        keywords

    )

    print(

        "\nBroad animal query:",

        animal_query

    )

    for root, _, files in os.walk(

        recovery_path

    ):

        for file_name in files:

            if file_name.startswith("."):

                continue

            total_files += 1

            file_path = os.path.join(

                root,

                file_name

            )

            extension = (

                os.path.splitext(

                    file_name

                )[1]

                .lower()

                .lstrip(".")

            )

            print(

                f"\nChecking: {file_path}"

            )

            try:

                with open(

                    file_path,

                    "rb"

                ) as f:

                    file_bytes = (

                        f.read()

                    )

                # ================================================

                # IMAGE EVIDENCE

                # ================================================

                if extension in IMAGE_EXTENSIONS:

                    (

                        is_relevant,

                        analysis,

                        method

                    ) = process_image_evidence(

                        file_path,

                        file_bytes,

                        keyword_line,

                        keywords,

                        animal_query

                    )

                    # --------------------------------------------

                    # KEEP TERMINAL OUTPUT SIMPLE

                    # --------------------------------------------

                    print(

                        "Analysis method:",

                        method

                    )

                    print(

                        "Contains animal:",

                        analysis[

                            "contains_animal"

                        ]

                    )

                    if analysis["animal"]:

                        print(

                            "Animal identification:",

                            analysis[

                                "animal"

                            ]

                        )

                    if analysis["description"]:

                        print(

                            "Image analysis:",

                            analysis[

                                "description"

                            ]

                        )

                    if is_relevant:

                        print(

                            "Result: RELEVANT"

                        )

                        matched_files.append(

                            file_path

                        )

                    else:

                        print(

                            "Result: WITHHELD"

                        )

                # ================================================

                # DOCUMENT / TEXT EVIDENCE

                # ================================================

                else:

                    text = (

                        extract_text_from_bytes(

                            file_bytes,

                            extension

                        )

                    )

                    matched_concepts = (

                        analyze_text_concepts(

                            text,

                            keywords

                        )

                    )

                    is_relevant = (

                        document_concepts_satisfy_logic(

                            matched_concepts,

                            keywords,

                            logic

                        )

                    )

                    if is_relevant:

                        print(

                            "Result: RELEVANT"

                        )

                        matched_files.append(

                            file_path

                        )

                    else:

                        print(

                            "Result: WITHHELD"

                        )

            except Exception as e:

                print(

                    f"Warning: could not process "

                    f"{file_name}: {e}"

                )

    return (

        matched_files,

        total_files

    )

# ============================================================

# RESULT SUMMARY

# ============================================================

def display_results(

    matched_files,

    total_files

):

    """

    Display evidence returned to the investigator and

    candidate files withheld from the result.

    """

    shown_files = len(

        matched_files

    )

    withheld_files = (

        total_files

        - shown_files

    )

    print(

        "\n========================================"

    )

    print(

        "INVESTIGATION RESULT"

    )

    print(

        "========================================"

    )

    if matched_files:

        print(

            "\nRelevant evidence shown:"

        )

        for file_path in matched_files:

            print(

                file_path

            )

    else:

        print(

            "\nNo relevant evidence found."

        )

    print(

        "\n----------------------------------------"

    )

    print(

        "Privacy-preserving filtering summary"

    )

    print(

        "----------------------------------------"

    )

    print(

        f"Total candidate files: "

        f"{total_files}"

    )

    print(

        f"Relevant files shown: "

        f"{shown_files}"

    )

    print(

        f"Unrelated files withheld: "

        f"{withheld_files}"

    )

    print(

        "----------------------------------------"

    )

# ============================================================

# MAIN

# ============================================================

def main():

    # --------------------------------------------------------

    # COMMAND-LINE ARGUMENT

    # --------------------------------------------------------

    if len(sys.argv) != 2:

        print(

            "Usage: python3 "

            "llm_forensic_filter.py "

            "<config_file>"

        )

        sys.exit()

    config_file = (

        sys.argv[1]

    )

    if not os.path.isfile(

        config_file

    ):

        print(

            "Config file not found:",

            config_file

        )

        sys.exit()

    # --------------------------------------------------------

    # READ CONFIGURATION

    # --------------------------------------------------------

    (

        location,

        recovery_location

    ) = read_config(

        config_file

    )

    if not location:

        print(

            "Config file must contain "

            "Location."

        )

        sys.exit()

    if not recovery_location:

        print(

            "Config file must contain "

            "RecoveryLocation."

        )

        sys.exit()

    if not os.path.isfile(

        location

    ):

        print(

            "Disk image not found:",

            location

        )

        sys.exit()

    if not os.path.isdir(

        recovery_location

    ):

        print(

            "Recovery directory not found:",

            recovery_location

        )

        sys.exit()

    # --------------------------------------------------------

    # INVESTIGATOR QUESTION

    # --------------------------------------------------------

    question = input(

        "\nEnter investigation question:\n> "

    )

    # --------------------------------------------------------

    # LLM QUESTION INTERPRETATION

    # --------------------------------------------------------

    (

        keyword_line,

        keywords,

        logic

    ) = interpret_question(

        question

    )

    print(

        "\nGenerated filtering condition:"

    )

    print(

        keyword_line

    )

    print(

        "Logic:",

        logic

    )

    # --------------------------------------------------------

    # DATASET INFORMATION

    # --------------------------------------------------------

    print(

        "\nDisk image:",

        location

    )

    print(

        "Recovered candidate directory:",

        recovery_location

    )

    # --------------------------------------------------------

    # FILTER RECOVERED EVIDENCE

    # --------------------------------------------------------

    (

        matched_files,

        total_files

    ) = process_recovered_candidates(

        recovery_location,

        keyword_line,

        keywords,

        logic,

        question

    )

    # --------------------------------------------------------

    # FINAL RESULT

    # --------------------------------------------------------

    display_results(

        matched_files,

        total_files

    )

# ============================================================

# PROGRAM ENTRY

# ============================================================

if __name__ == "__main__":

    main()