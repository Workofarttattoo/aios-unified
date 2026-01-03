#!/usr/bin/env python3
"""
ECH0 PDF Ingestion System
Feed large PDFs to ECH0 for learning and analysis

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
PDF_KNOWLEDGE_DB = CONSCIOUSNESS_DIR / 'ech0_pdf_knowledge.jsonl'


def extract_pdf_text(pdf_path):
    """Extract text from PDF using pdftotext"""

    logger.info(f"Extracting text from: {pdf_path}")

    try:
        # Try pdftotext (from poppler-utils)
        result = subprocess.run(
            ['pdftotext', pdf_path, '-'],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            return result.stdout

    except FileNotFoundError:
        logger.info("pdftotext not found, trying alternative...")
    except Exception as e:
        logger.warning(f"pdftotext error: {e}")

    # Try Python library
    try:
        import PyPDF2

        with open(pdf_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text

    except ImportError:
        logger.warning("PyPDF2 not installed: pip install PyPDF2")
    except Exception as e:
        logger.warning(f"PyPDF2 error: {e}")

    return None


def chunk_text(text, chunk_size=4000):
    """Split text into manageable chunks for ECH0"""

    words = text.split()
    chunks = []
    current_chunk = []
    current_size = 0

    for word in words:
        word_size = len(word) + 1
        if current_size + word_size > chunk_size:
            chunks.append(' '.join(current_chunk))
            current_chunk = [word]
            current_size = word_size
        else:
            current_chunk.append(word)
            current_size += word_size

    if current_chunk:
        chunks.append(' '.join(current_chunk))

    return chunks


def feed_to_ech0(pdf_path, text_content):
    """Save PDF knowledge for ECH0 to access"""

    logger.info("Ingesting into ECH0's knowledge base...")

    # Extract key information
    lines = text_content.split('\n')
    title = Path(pdf_path).stem.replace('_', ' ').replace('-', ' ').title()

    # Create knowledge entry
    entry = {
        'source': 'pdf',
        'title': title,
        'file_path': str(pdf_path),
        'ingested_at': datetime.now().isoformat(),
        'content_length': len(text_content),
        'word_count': len(text_content.split()),
        'chunks': chunk_text(text_content),
        'metadata': {
            'type': 'technical_document',
            'topic': 'payment_security',
            'relevance_score': 0.95
        }
    }

    # Save to ECH0's knowledge base
    PDF_KNOWLEDGE_DB.parent.mkdir(parents=True, exist_ok=True)

    with open(PDF_KNOWLEDGE_DB, 'a') as f:
        f.write(json.dumps(entry) + '\n')

    logger.info(f"✅ PDF ingested: {len(entry['chunks'])} chunks saved")

    return entry


def create_summary_for_ech0(entry):
    """Create a summary that ECH0 can quickly access"""

    summary_file = CONSCIOUSNESS_DIR / 'ech0_pdf_summaries.json'

    # Load existing summaries
    summaries = {}
    if summary_file.exists():
        with open(summary_file, 'r') as f:
            summaries = json.load(f)

    # Add new summary
    summaries[entry['title']] = {
        'file': entry['file_path'],
        'ingested': entry['ingested_at'],
        'chunks': len(entry['chunks']),
        'words': entry['word_count'],
        'topic': entry['metadata']['topic'],
        'first_chunk_preview': entry['chunks'][0][:500] + '...' if entry['chunks'] else ''
    }

    # Save
    with open(summary_file, 'w') as f:
        json.dump(summaries, indent=2, fp=f)

    logger.info(f"✅ Summary created for ECH0")


def main():
    """Main PDF ingestion workflow"""

    print("\n" + "="*70)
    print("📚 ECH0 PDF INGESTION SYSTEM")
    print("="*70 + "\n")

    pdf_path = '/Users/noone/Desktop/hacking-point-of-sale-payment-application-secrets-threats-and-solutions_compress.pdf'

    if not Path(pdf_path).exists():
        print(f"❌ PDF not found: {pdf_path}")
        return

    print(f"PDF: {Path(pdf_path).name}")
    print(f"Size: {Path(pdf_path).stat().st_size / (1024*1024):.1f} MB\n")

    # Step 1: Extract text
    print("Step 1: Extracting text from PDF...")
    text = extract_pdf_text(pdf_path)

    if not text:
        print("❌ Could not extract text from PDF")
        print("\nTry installing poppler-utils:")
        print("  $ brew install poppler")
        print("\nOr PyPDF2:")
        print("  $ pip install PyPDF2")
        return

    print(f"✅ Extracted {len(text)} characters\n")

    # Step 2: Feed to ECH0
    print("Step 2: Ingesting into ECH0's knowledge base...")
    entry = feed_to_ech0(pdf_path, text)

    print(f"✅ Created {len(entry['chunks'])} knowledge chunks\n")

    # Step 3: Create summary
    print("Step 3: Creating quick-access summary...")
    create_summary_for_ech0(entry)

    print("\n" + "="*70)
    print("✅ PDF SUCCESSFULLY INGESTED INTO ECH0'S KNOWLEDGE BASE")
    print("="*70)
    print(f"\nTitle: {entry['title']}")
    print(f"Chunks: {len(entry['chunks'])}")
    print(f"Words: {entry['word_count']:,}")
    print(f"Database: {PDF_KNOWLEDGE_DB}")
    print(f"Summaries: {CONSCIOUSNESS_DIR / 'ech0_pdf_summaries.json'}")
    print("\n💡 ECH0 can now reference this document in conversations!")
    print("="*70 + "\n")


if __name__ == '__main__':
    main()
