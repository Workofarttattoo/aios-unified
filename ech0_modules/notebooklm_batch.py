#!/usr/bin/env python3
"""
NotebookLM Batch Processor for ECH0 Training
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Batch processes hundreds of courses through NotebookLM:
- Parallel processing for speed
- Automatic retry on failures
- Progress tracking and checkpointing
- Resource management (memory, GPU)
- Incremental updates
"""

import asyncio
import aiohttp
import json
import pickle
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import torch
import psutil
import gc
from tqdm.asyncio import tqdm

from notebooklm_pipeline import NotebookLMPipeline, NotebookLMModel
from mit_ocw_scraper import Course

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BatchProcessingConfig:
    """Configuration for batch processing."""
    max_concurrent: int = 4  # Max concurrent processing
    max_retries: int = 3  # Max retries per course
    checkpoint_interval: int = 10  # Save checkpoint every N courses
    memory_limit_gb: float = 16.0  # Max memory usage
    gpu_memory_fraction: float = 0.8  # Fraction of GPU memory to use
    timeout_minutes: int = 30  # Timeout per course
    use_multiprocessing: bool = True  # Use multiprocessing for CPU-bound tasks


@dataclass
class ProcessingStatus:
    """Status of batch processing job."""
    total_courses: int
    processed_courses: int
    failed_courses: List[str]
    skipped_courses: List[str]
    processing_time: timedelta
    estimated_remaining: timedelta
    current_course: Optional[str]
    memory_usage_gb: float
    gpu_usage_percent: float


class NotebookLMBatchProcessor:
    """Batch processor for NotebookLM training."""

    def __init__(self, config: BatchProcessingConfig = None):
        """Initialize batch processor."""
        self.config = config or BatchProcessingConfig()
        self.pipeline = NotebookLMPipeline()

        # Processing state
        self.processing_status = None
        self.checkpoint_file = Path("/Users/noone/aios/ech0_models/batch_checkpoint.json")
        self.processed_courses = set()
        self.failed_courses = {}
        self.models_cache = {}

        # Resource management
        self._setup_resource_limits()

    def _setup_resource_limits(self):
        """Setup resource limits for processing."""
        if torch.cuda.is_available():
            # Set GPU memory fraction
            torch.cuda.set_per_process_memory_fraction(self.config.gpu_memory_fraction)

        # Monitor memory usage
        self.initial_memory = psutil.virtual_memory().used / (1024**3)  # GB

    async def process_all_courses(self,
                                 courses: List[Course],
                                 resume_from_checkpoint: bool = True) -> Dict[str, NotebookLMModel]:
        """
        Process all courses through NotebookLM.

        Args:
            courses: List of courses to process
            resume_from_checkpoint: Whether to resume from last checkpoint

        Returns:
            Dictionary mapping course IDs to NotebookLM models
        """
        logger.info(f"Starting batch processing of {len(courses)} courses")

        # Load checkpoint if resuming
        if resume_from_checkpoint:
            self._load_checkpoint()

        # Filter already processed courses
        courses_to_process = [
            c for c in courses
            if c.course_id not in self.processed_courses
        ]

        logger.info(f"Courses to process: {len(courses_to_process)}")
        logger.info(f"Already processed: {len(self.processed_courses)}")

        # Initialize status
        self.processing_status = ProcessingStatus(
            total_courses=len(courses),
            processed_courses=len(self.processed_courses),
            failed_courses=list(self.failed_courses.keys()),
            skipped_courses=[],
            processing_time=timedelta(),
            estimated_remaining=timedelta(),
            current_course=None,
            memory_usage_gb=0,
            gpu_usage_percent=0
        )

        # Process in batches
        start_time = datetime.now()
        models = {}

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        # Process courses with progress bar
        tasks = []
        async with tqdm(total=len(courses_to_process), desc="Processing courses") as pbar:
            for course in courses_to_process:
                task = self._process_course_with_semaphore(course, semaphore, pbar)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful models
        for i, result in enumerate(results):
            if isinstance(result, NotebookLMModel):
                models[courses_to_process[i].course_id] = result
            elif isinstance(result, Exception):
                logger.error(f"Failed to process {courses_to_process[i].course_id}: {result}")
                self.failed_courses[courses_to_process[i].course_id] = str(result)

        # Update final status
        self.processing_status.processing_time = datetime.now() - start_time
        self.processing_status.processed_courses = len(self.processed_courses)

        # Save final checkpoint
        self._save_checkpoint()

        logger.info(f"Batch processing complete. Processed: {len(models)}, Failed: {len(self.failed_courses)}")

        return models

    async def _process_course_with_semaphore(self,
                                            course: Course,
                                            semaphore: asyncio.Semaphore,
                                            pbar: tqdm) -> Optional[NotebookLMModel]:
        """Process course with semaphore for concurrency control."""
        async with semaphore:
            result = await self._process_single_course(course)
            pbar.update(1)

            # Update status
            self._update_status(course.course_id)

            # Checkpoint periodically
            if len(self.processed_courses) % self.config.checkpoint_interval == 0:
                self._save_checkpoint()

            return result

    async def _process_single_course(self, course: Course) -> Optional[NotebookLMModel]:
        """
        Process a single course with retry logic.

        Args:
            course: Course to process

        Returns:
            NotebookLM model or None if failed
        """
        course_id = course.course_id

        # Check memory before processing
        if not self._check_memory():
            logger.warning(f"Memory limit exceeded, skipping {course_id}")
            self.processing_status.skipped_courses.append(course_id)
            return None

        # Try processing with retries
        for attempt in range(self.config.max_retries):
            try:
                logger.info(f"Processing {course_id} (attempt {attempt + 1})")

                # Set timeout
                timeout = self.config.timeout_minutes * 60  # seconds

                # Convert Course to dict format expected by pipeline
                course_data = {
                    'course_id': course.course_id,
                    'title': course.title,
                    'university': course.university,
                    'department': course.department,
                    'level': course.level,
                    'transcripts': course.transcripts,
                    'lecture_notes': course.lecture_notes,
                    'problem_sets': course.problem_sets,
                    'exams': course.exams,
                    'materials': course.materials
                }

                # Process with timeout
                model = await asyncio.wait_for(
                    self.pipeline.process_course(course_data),
                    timeout=timeout
                )

                # Mark as processed
                self.processed_courses.add(course_id)

                # Cache model
                self.models_cache[course_id] = model

                return model

            except asyncio.TimeoutError:
                logger.error(f"Timeout processing {course_id} (attempt {attempt + 1})")
                if attempt == self.config.max_retries - 1:
                    self.failed_courses[course_id] = "Timeout"

            except Exception as e:
                logger.error(f"Error processing {course_id} (attempt {attempt + 1}): {e}")
                if attempt == self.config.max_retries - 1:
                    self.failed_courses[course_id] = str(e)

                # Clean up on error
                self._cleanup_resources()

        return None

    def _check_memory(self) -> bool:
        """Check if memory usage is within limits."""
        current_memory = psutil.virtual_memory().used / (1024**3)  # GB
        memory_used = current_memory - self.initial_memory

        self.processing_status.memory_usage_gb = memory_used

        if memory_used > self.config.memory_limit_gb:
            logger.warning(f"Memory usage: {memory_used:.2f} GB exceeds limit {self.config.memory_limit_gb} GB")

            # Try garbage collection
            gc.collect()

            # Clear cache if needed
            if len(self.models_cache) > 10:
                self.models_cache.clear()

            # Recheck
            current_memory = psutil.virtual_memory().used / (1024**3)
            memory_used = current_memory - self.initial_memory

            return memory_used <= self.config.memory_limit_gb

        return True

    def _cleanup_resources(self):
        """Clean up resources to free memory."""
        # Clear PyTorch cache
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

        # Garbage collection
        gc.collect()

        # Clear old models from cache
        if len(self.models_cache) > 20:
            # Keep only last 10 models
            keep_ids = list(self.models_cache.keys())[-10:]
            self.models_cache = {k: v for k, v in self.models_cache.items() if k in keep_ids}

    def _update_status(self, current_course: str):
        """Update processing status."""
        if self.processing_status:
            self.processing_status.current_course = current_course

            # Update GPU usage if available
            if torch.cuda.is_available():
                self.processing_status.gpu_usage_percent = \
                    torch.cuda.memory_allocated() / torch.cuda.max_memory_allocated() * 100

            # Estimate remaining time
            if self.processing_status.processed_courses > 0:
                avg_time = self.processing_status.processing_time / self.processing_status.processed_courses
                remaining_courses = self.processing_status.total_courses - self.processing_status.processed_courses
                self.processing_status.estimated_remaining = avg_time * remaining_courses

    def _save_checkpoint(self):
        """Save processing checkpoint."""
        checkpoint = {
            'processed_courses': list(self.processed_courses),
            'failed_courses': self.failed_courses,
            'timestamp': datetime.now().isoformat()
        }

        with open(self.checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)

        logger.info(f"Checkpoint saved: {len(self.processed_courses)} processed")

    def _load_checkpoint(self):
        """Load processing checkpoint."""
        if self.checkpoint_file.exists():
            with open(self.checkpoint_file, 'r') as f:
                checkpoint = json.load(f)

            self.processed_courses = set(checkpoint.get('processed_courses', []))
            self.failed_courses = checkpoint.get('failed_courses', {})

            logger.info(f"Checkpoint loaded: {len(self.processed_courses)} previously processed")

    async def parallel_scrape_and_process(self,
                                         course_urls: List[str]) -> Dict[str, NotebookLMModel]:
        """
        Scrape and process courses in parallel.

        Args:
            course_urls: List of course URLs to scrape and process

        Returns:
            Dictionary of processed models
        """
        logger.info(f"Parallel scraping and processing {len(course_urls)} courses")

        # Create tasks for scraping
        scrape_tasks = []
        async with aiohttp.ClientSession() as session:
            for url in course_urls:
                task = self._scrape_course_async(session, url)
                scrape_tasks.append(task)

            # Scrape all courses
            scraped_courses = await asyncio.gather(*scrape_tasks)

        # Filter out failed scrapes
        valid_courses = [c for c in scraped_courses if c is not None]

        logger.info(f"Successfully scraped {len(valid_courses)} courses")

        # Process scraped courses
        models = await self.process_all_courses(valid_courses)

        return models

    async def _scrape_course_async(self,
                                  session: aiohttp.ClientSession,
                                  url: str) -> Optional[Course]:
        """Scrape course asynchronously."""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    # Parse course data (simplified)
                    # In real implementation, use full scraper
                    course = Course(
                        course_id=url.split('/')[-1],
                        title=f"Course from {url}",
                        department="Unknown",
                        level="undergraduate",
                        university="MIT",
                        instructor="Unknown",
                        semester="Unknown",
                        materials={},
                        transcripts=[],
                        problem_sets=[],
                        exams=[],
                        lecture_notes=[]
                    )
                    return course
        except Exception as e:
            logger.error(f"Failed to scrape {url}: {e}")
            return None

    def get_processing_report(self) -> Dict[str, Any]:
        """Get detailed processing report."""
        report = {
            'summary': {
                'total_courses': self.processing_status.total_courses if self.processing_status else 0,
                'processed': len(self.processed_courses),
                'failed': len(self.failed_courses),
                'success_rate': len(self.processed_courses) / max(len(self.processed_courses) + len(self.failed_courses), 1) * 100
            },
            'failed_courses': self.failed_courses,
            'resource_usage': {
                'memory_gb': self.processing_status.memory_usage_gb if self.processing_status else 0,
                'gpu_percent': self.processing_status.gpu_usage_percent if self.processing_status else 0
            },
            'timing': {
                'total_time': str(self.processing_status.processing_time) if self.processing_status else "0:00:00",
                'avg_per_course': str(self.processing_status.processing_time / max(len(self.processed_courses), 1)) if self.processing_status else "0:00:00"
            }
        }

        return report

    async def reprocess_failed_courses(self) -> Dict[str, NotebookLMModel]:
        """Reprocess courses that failed previously."""
        logger.info(f"Reprocessing {len(self.failed_courses)} failed courses")

        # Get failed course objects
        failed_course_ids = list(self.failed_courses.keys())

        # Clear failed courses for retry
        self.failed_courses.clear()

        # Create dummy courses for reprocessing (in real implementation, reload from disk)
        courses_to_retry = [
            Course(
                course_id=course_id,
                title=f"Course {course_id}",
                department="Unknown",
                level="undergraduate",
                university="MIT",
                instructor="Unknown",
                semester="Unknown",
                materials={},
                transcripts=[],
                problem_sets=[],
                exams=[],
                lecture_notes=[]
            )
            for course_id in failed_course_ids
        ]

        # Process with increased timeout
        original_timeout = self.config.timeout_minutes
        self.config.timeout_minutes *= 2  # Double timeout for retries

        models = await self.process_all_courses(courses_to_retry, resume_from_checkpoint=False)

        # Restore original timeout
        self.config.timeout_minutes = original_timeout

        return models


class DistributedBatchProcessor:
    """Distributed batch processor for multi-node processing."""

    def __init__(self, num_workers: int = 4):
        """Initialize distributed processor."""
        self.num_workers = num_workers
        self.executor = ProcessPoolExecutor(max_workers=num_workers)

    async def distributed_process(self,
                                 courses: List[Course]) -> Dict[str, NotebookLMModel]:
        """
        Process courses across multiple workers.

        Args:
            courses: Courses to process

        Returns:
            Processed models
        """
        logger.info(f"Starting distributed processing with {self.num_workers} workers")

        # Split courses among workers
        chunk_size = len(courses) // self.num_workers
        course_chunks = [
            courses[i:i + chunk_size]
            for i in range(0, len(courses), chunk_size)
        ]

        # Process chunks in parallel
        loop = asyncio.get_event_loop()
        futures = []

        for chunk in course_chunks:
            future = loop.run_in_executor(
                self.executor,
                self._process_chunk,
                chunk
            )
            futures.append(future)

        # Gather results
        results = await asyncio.gather(*futures)

        # Merge results
        all_models = {}
        for models in results:
            all_models.update(models)

        return all_models

    def _process_chunk(self, courses: List[Course]) -> Dict[str, NotebookLMModel]:
        """Process a chunk of courses (runs in separate process)."""
        # Create new event loop for this process
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Create processor
        processor = NotebookLMBatchProcessor()

        # Process courses
        models = loop.run_until_complete(
            processor.process_all_courses(courses, resume_from_checkpoint=False)
        )

        return models


async def main():
    """Main entry point for batch processing."""
    print("\n=== NotebookLM Batch Processor ===\n")

    # Create sample courses
    sample_courses = [
        Course(
            course_id=f"course_{i}",
            title=f"Sample Course {i}",
            department="Computer Science",
            level="undergraduate",
            university="MIT",
            instructor="Professor X",
            semester="Fall 2024",
            materials={'videos': [], 'pdfs': []},
            transcripts=[{'transcript': f'Lecture {i} content...'}],
            problem_sets=[],
            exams=[],
            lecture_notes=[]
        )
        for i in range(5)
    ]

    # Configure batch processor
    config = BatchProcessingConfig(
        max_concurrent=2,
        max_retries=2,
        checkpoint_interval=2,
        memory_limit_gb=8.0
    )

    # Create processor
    processor = NotebookLMBatchProcessor(config)

    # Process courses
    models = await processor.process_all_courses(sample_courses)

    # Get report
    report = processor.get_processing_report()

    print("\n=== Processing Report ===")
    print(f"Processed: {report['summary']['processed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Success Rate: {report['summary']['success_rate']:.1f}%")
    print(f"Total Time: {report['timing']['total_time']}")
    print(f"Memory Usage: {report['resource_usage']['memory_gb']:.2f} GB")

    # Test distributed processing
    print("\n=== Testing Distributed Processing ===")
    distributed = DistributedBatchProcessor(num_workers=2)
    distributed_models = await distributed.distributed_process(sample_courses[:2])
    print(f"Distributed processing completed: {len(distributed_models)} models")


if __name__ == "__main__":
    asyncio.run(main())