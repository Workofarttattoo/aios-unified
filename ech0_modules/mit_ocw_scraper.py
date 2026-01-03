#!/usr/bin/env python3
"""
MIT OpenCourseWare and University Content Scraper
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Scrapes educational content from:
- MIT OpenCourseWare (ocw.mit.edu)
- Stanford Online (online.stanford.edu)
- YouTube educational channels
- ArXiv papers
- iTunes U content

Extracts:
- Video transcripts
- Lecture PDFs
- Problem sets and solutions
- Exams and answer keys
- Course materials
"""

import asyncio
import aiohttp
import json
import re
import os
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from bs4 import BeautifulSoup
import PyPDF2
import youtube_dl
from concurrent.futures import ThreadPoolExecutor
import hashlib
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Course:
    """Represents a university course with all materials."""

    course_id: str
    title: str
    department: str
    level: str  # undergraduate, graduate
    university: str
    instructor: str
    semester: str
    materials: Dict[str, List[str]]  # type -> list of URLs
    transcripts: List[Dict[str, str]]
    problem_sets: List[Dict[str, str]]
    exams: List[Dict[str, str]]
    lecture_notes: List[Dict[str, str]]

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'course_id': self.course_id,
            'title': self.title,
            'department': self.department,
            'level': self.level,
            'university': self.university,
            'instructor': self.instructor,
            'semester': self.semester,
            'materials': self.materials,
            'transcripts': self.transcripts,
            'problem_sets': self.problem_sets,
            'exams': self.exams,
            'lecture_notes': self.lecture_notes
        }


class MITOpenCourseWareScraper:
    """Scrapes MIT OpenCourseWare for all course materials."""

    BASE_URL = "https://ocw.mit.edu"

    # Core domains for ECH0 training
    DOMAINS = {
        'mathematics': ['18', '6.042'],  # Course 18 is math
        'physics': ['8'],  # Course 8 is physics
        'engineering': ['2', '3', '6', '10', '16', '20'],  # Various engineering
        'computer_science': ['6', '6.001', '6.006', '6.034'],
        'aerospace': ['16', '16.00', '16.07', '16.50'],  # Rocket propulsion
    }

    # Priority courses for ECH0
    PRIORITY_COURSES = [
        '18.01',  # Single Variable Calculus
        '18.02',  # Multivariable Calculus
        '18.03',  # Differential Equations
        '18.06',  # Linear Algebra
        '8.01',   # Classical Mechanics
        '8.02',   # Electricity and Magnetism
        '8.04',   # Quantum Mechanics
        '8.05',   # Statistical Mechanics
        '6.001',  # Structure and Interpretation of Computer Programs
        '6.006',  # Introduction to Algorithms
        '6.034',  # Artificial Intelligence
        '16.50',  # Rocket Propulsion
        '16.07',  # Dynamics
        '2.003',  # Dynamics and Control I
        '3.091',  # Introduction to Solid State Chemistry
    ]

    def __init__(self, output_dir: str = "/Users/noone/aios/ech0_training_data"):
        """Initialize scraper with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = None
        self.scraped_courses = []

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def fetch_page(self, url: str) -> str:
        """Fetch page content asynchronously."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    logger.warning(f"Failed to fetch {url}: {response.status}")
                    return ""
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return ""

    async def scrape_course_catalog(self) -> List[Dict[str, str]]:
        """Scrape entire MIT OCW course catalog."""
        catalog = []

        # Fetch course listing pages
        for domain, course_numbers in self.DOMAINS.items():
            for course_num in course_numbers:
                search_url = f"{self.BASE_URL}/search/?q={course_num}"
                html = await self.fetch_page(search_url)

                if html:
                    soup = BeautifulSoup(html, 'html.parser')

                    # Extract course links
                    course_links = soup.find_all('h2', class_='course-title')
                    for link in course_links:
                        course_url = link.find('a')['href']
                        course_title = link.get_text(strip=True)

                        catalog.append({
                            'domain': domain,
                            'url': f"{self.BASE_URL}{course_url}",
                            'title': course_title,
                            'course_number': course_num
                        })

        logger.info(f"Found {len(catalog)} courses in catalog")
        return catalog

    async def scrape_course(self, course_info: Dict[str, str]) -> Optional[Course]:
        """Scrape individual course for all materials."""
        url = course_info['url']

        html = await self.fetch_page(url)
        if not html:
            return None

        soup = BeautifulSoup(html, 'html.parser')

        # Extract course metadata
        course = Course(
            course_id=course_info['course_number'],
            title=course_info['title'],
            department=course_info['domain'],
            level='undergraduate' if int(course_info['course_number'].split('.')[0]) < 100 else 'graduate',
            university='MIT',
            instructor=self._extract_instructor(soup),
            semester=self._extract_semester(soup),
            materials={'videos': [], 'pdfs': [], 'assignments': []},
            transcripts=[],
            problem_sets=[],
            exams=[],
            lecture_notes=[]
        )

        # Extract all materials
        await self._extract_videos(soup, course)
        await self._extract_pdfs(soup, course)
        await self._extract_assignments(soup, course)
        await self._extract_exams(soup, course)

        return course

    def _extract_instructor(self, soup: BeautifulSoup) -> str:
        """Extract instructor name from course page."""
        instructor_elem = soup.find('p', class_='instructor')
        if instructor_elem:
            return instructor_elem.get_text(strip=True)
        return "Unknown"

    def _extract_semester(self, soup: BeautifulSoup) -> str:
        """Extract semester information."""
        semester_elem = soup.find('p', class_='semester')
        if semester_elem:
            return semester_elem.get_text(strip=True)
        return "Unknown"

    async def _extract_videos(self, soup: BeautifulSoup, course: Course):
        """Extract video lectures and transcripts."""
        video_links = soup.find_all('a', href=re.compile(r'\.mp4|youtube\.com|youtu\.be'))

        for link in video_links:
            video_url = link.get('href')
            if not video_url.startswith('http'):
                video_url = f"{self.BASE_URL}{video_url}"

            course.materials['videos'].append(video_url)

            # Try to get transcript
            transcript_url = video_url.replace('.mp4', '_transcript.pdf')
            transcript = await self.fetch_page(transcript_url)
            if transcript:
                course.transcripts.append({
                    'video_url': video_url,
                    'transcript': transcript
                })

    async def _extract_pdfs(self, soup: BeautifulSoup, course: Course):
        """Extract all PDF materials."""
        pdf_links = soup.find_all('a', href=re.compile(r'\.pdf'))

        for link in pdf_links:
            pdf_url = link.get('href')
            if not pdf_url.startswith('http'):
                pdf_url = f"{self.BASE_URL}{pdf_url}"

            # Categorize PDF by name
            pdf_name = link.get_text(strip=True).lower()

            if 'lecture' in pdf_name or 'notes' in pdf_name:
                course.lecture_notes.append({
                    'title': link.get_text(strip=True),
                    'url': pdf_url
                })
            elif 'problem' in pdf_name or 'pset' in pdf_name or 'assignment' in pdf_name:
                course.problem_sets.append({
                    'title': link.get_text(strip=True),
                    'url': pdf_url
                })
            elif 'exam' in pdf_name or 'quiz' in pdf_name or 'test' in pdf_name:
                course.exams.append({
                    'title': link.get_text(strip=True),
                    'url': pdf_url
                })
            else:
                course.materials['pdfs'].append(pdf_url)

    async def _extract_assignments(self, soup: BeautifulSoup, course: Course):
        """Extract assignments and problem sets."""
        assignments_section = soup.find('section', id='assignments')
        if assignments_section:
            assignment_links = assignments_section.find_all('a')

            for link in assignment_links:
                url = link.get('href')
                if url and not url.startswith('#'):
                    if not url.startswith('http'):
                        url = f"{self.BASE_URL}{url}"

                    course.materials['assignments'].append(url)
                    course.problem_sets.append({
                        'title': link.get_text(strip=True),
                        'url': url
                    })

    async def _extract_exams(self, soup: BeautifulSoup, course: Course):
        """Extract exams and solutions."""
        exams_section = soup.find('section', id='exams')
        if exams_section:
            exam_links = exams_section.find_all('a')

            for link in exam_links:
                url = link.get('href')
                if url and not url.startswith('#'):
                    if not url.startswith('http'):
                        url = f"{self.BASE_URL}{url}"

                    course.exams.append({
                        'title': link.get_text(strip=True),
                        'url': url,
                        'has_solution': 'solution' in link.get_text(strip=True).lower()
                    })

    async def scrape_priority_courses(self) -> List[Course]:
        """Scrape all priority courses for ECH0 training."""
        courses = []

        for course_num in self.PRIORITY_COURSES:
            logger.info(f"Scraping priority course: {course_num}")

            # Determine domain
            domain = 'mathematics' if course_num.startswith('18') else \
                    'physics' if course_num.startswith('8') else \
                    'engineering' if course_num.startswith('16') else \
                    'computer_science'

            course_info = {
                'course_number': course_num,
                'domain': domain,
                'url': f"{self.BASE_URL}/courses/{course_num.replace('.', '-')}",
                'title': f"Course {course_num}"
            }

            course = await self.scrape_course(course_info)
            if course:
                courses.append(course)
                # Save course data
                self.save_course(course)

        return courses

    def save_course(self, course: Course):
        """Save course data to disk."""
        course_dir = self.output_dir / course.university / course.course_id
        course_dir.mkdir(parents=True, exist_ok=True)

        # Save course metadata
        metadata_file = course_dir / 'course_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(course.to_dict(), f, indent=2)

        logger.info(f"Saved course {course.course_id} to {course_dir}")


class StanfordOnlineScraper:
    """Scrapes Stanford Online courses."""

    BASE_URL = "https://online.stanford.edu"

    async def scrape_courses(self) -> List[Course]:
        """Scrape Stanford courses similar to MIT."""
        # Implementation similar to MIT scraper
        pass


class YouTubeEducationalScraper:
    """Scrapes educational YouTube channels."""

    CHANNELS = [
        'UCEBb1b_L6zDS3xTUrIALZOw',  # MIT OpenCourseWare
        'UCosXPb1MbqY1v6F3ee-ztcQ',  # Stanford Online
        'UC_7kNqJ8u9kv5B-AaWsOKHA',  # Caltech
        'UCYO_jab_esuFRV4b17AJtAw',  # 3Blue1Brown (math)
        'UCoxcjq-8xIDTYp3uz647V5A',  # Numberphile (math)
        'UC7_gcs09iThXybpVgjHZ_7g',  # PBS Space Time (physics)
    ]

    def __init__(self, output_dir: str = "/Users/noone/aios/ech0_training_data/youtube"):
        """Initialize YouTube scraper."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def scrape_channel(self, channel_id: str) -> List[Dict[str, Any]]:
        """Scrape all videos from a channel."""
        ydl_opts = {
            'quiet': True,
            'extract_flat': True,
            'dump_single_json': True
        }

        videos = []
        with youtube_dl.YoutubeDL(ydl_opts) as ydl:
            try:
                url = f"https://www.youtube.com/channel/{channel_id}/videos"
                info = ydl.extract_info(url, download=False)

                for entry in info.get('entries', []):
                    video_data = {
                        'title': entry.get('title'),
                        'url': f"https://www.youtube.com/watch?v={entry.get('id')}",
                        'duration': entry.get('duration'),
                        'channel': channel_id
                    }

                    # Get transcript if available
                    transcript = await self.get_transcript(entry.get('id'))
                    if transcript:
                        video_data['transcript'] = transcript

                    videos.append(video_data)

            except Exception as e:
                logger.error(f"Error scraping channel {channel_id}: {e}")

        return videos

    async def get_transcript(self, video_id: str) -> Optional[str]:
        """Get transcript for a video using YouTube API."""
        # Use youtube-transcript-api or similar
        # Implementation details here
        pass


class ArXivScraper:
    """Scrapes ArXiv for relevant academic papers."""

    BASE_URL = "http://arxiv.org/api/query"

    CATEGORIES = [
        'math.CA',  # Calculus
        'math.DG',  # Differential Geometry
        'physics.class-ph',  # Classical Physics
        'quant-ph',  # Quantum Physics
        'cs.AI',    # Artificial Intelligence
        'cs.LG',    # Machine Learning
    ]

    async def scrape_papers(self, max_results: int = 100) -> List[Dict[str, str]]:
        """Scrape papers from ArXiv."""
        papers = []

        async with aiohttp.ClientSession() as session:
            for category in self.CATEGORIES:
                params = {
                    'search_query': f'cat:{category}',
                    'max_results': max_results,
                    'sortBy': 'relevance'
                }

                async with session.get(self.BASE_URL, params=params) as response:
                    if response.status == 200:
                        # Parse ArXiv API response
                        text = await response.text()
                        # Extract paper metadata
                        # Implementation details here

        return papers


class ComprehensiveEducationScraper:
    """Main scraper orchestrator for all educational content."""

    def __init__(self):
        """Initialize comprehensive scraper."""
        self.mit_scraper = MITOpenCourseWareScraper()
        self.stanford_scraper = StanfordOnlineScraper()
        self.youtube_scraper = YouTubeEducationalScraper()
        self.arxiv_scraper = ArXivScraper()

    async def scrape_all_content(self) -> Dict[str, List[Course]]:
        """Scrape all educational content from all sources."""
        logger.info("Starting comprehensive educational content scraping...")

        all_content = {
            'mit_courses': [],
            'stanford_courses': [],
            'youtube_videos': [],
            'arxiv_papers': []
        }

        # Scrape MIT OCW
        async with self.mit_scraper as scraper:
            all_content['mit_courses'] = await scraper.scrape_priority_courses()

        # Scrape Stanford
        all_content['stanford_courses'] = await self.stanford_scraper.scrape_courses()

        # Scrape YouTube
        for channel in self.youtube_scraper.CHANNELS:
            videos = await self.youtube_scraper.scrape_channel(channel)
            all_content['youtube_videos'].extend(videos)

        # Scrape ArXiv
        all_content['arxiv_papers'] = await self.arxiv_scraper.scrape_papers()

        # Save comprehensive dataset
        output_file = Path("/Users/noone/aios/ech0_training_data/complete_education_dataset.json")
        with open(output_file, 'w') as f:
            json.dump(all_content, f, indent=2)

        logger.info(f"Scraped {len(all_content['mit_courses'])} MIT courses")
        logger.info(f"Scraped {len(all_content['youtube_videos'])} YouTube videos")
        logger.info(f"Scraped {len(all_content['arxiv_papers'])} ArXiv papers")

        return all_content


async def main():
    """Main entry point for scraping."""
    scraper = ComprehensiveEducationScraper()
    content = await scraper.scrape_all_content()

    print(f"\n=== ECH0 Training Data Scraped ===")
    print(f"MIT Courses: {len(content['mit_courses'])}")
    print(f"YouTube Videos: {len(content['youtube_videos'])}")
    print(f"ArXiv Papers: {len(content['arxiv_papers'])}")
    print(f"\nData saved to: /Users/noone/aios/ech0_training_data/")


if __name__ == "__main__":
    asyncio.run(main())