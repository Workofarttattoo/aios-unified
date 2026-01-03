#!/usr/bin/env python3
"""
Curriculum Builder for ECH0 Training
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Automatically builds comprehensive MIT-level curriculum:
1. Scrapes course catalogs and prerequisites
2. Identifies dependencies between courses
3. Orders courses by difficulty and logical progression
4. Creates personalized learning paths
5. Generates assessments and tracks progress
"""

import json
import networkx as nx
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
import numpy as np
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Course:
    """Represents a course in the curriculum."""
    course_id: str
    title: str
    department: str
    level: int  # 1-100 for undergrad, 100+ for grad
    credits: int
    prerequisites: List[str] = field(default_factory=list)
    corequisites: List[str] = field(default_factory=list)
    description: str = ""
    topics: List[str] = field(default_factory=list)
    skills: List[str] = field(default_factory=list)
    estimated_hours: int = 150  # Default semester hours
    difficulty: float = 0.5  # 0-1 scale


@dataclass
class LearningPath:
    """Personalized learning path for ECH0."""
    path_id: str
    name: str
    goal: str
    courses: List[Course]
    total_hours: int
    estimated_duration: timedelta
    skill_coverage: Dict[str, float]
    difficulty_progression: List[float]


@dataclass
class AssessmentResult:
    """Result from an assessment."""
    course_id: str
    timestamp: datetime
    score: float
    topics_mastered: List[str]
    topics_to_review: List[str]
    time_taken: timedelta
    confidence_level: float


class MITCurriculumBuilder:
    """Builds MIT-level curriculum for ECH0."""

    # Core curriculum based on MIT requirements
    CORE_REQUIREMENTS = {
        'mathematics': [
            '18.01',  # Single Variable Calculus
            '18.02',  # Multivariable Calculus
            '18.03',  # Differential Equations
            '18.06',  # Linear Algebra
        ],
        'physics': [
            '8.01',   # Classical Mechanics
            '8.02',   # Electricity and Magnetism
        ],
        'computer_science': [
            '6.0001', # Intro to CS and Programming in Python
            '6.009',  # Fundamentals of Programming
            '6.006',  # Introduction to Algorithms
        ],
        'engineering': [
            '2.003',  # Dynamics and Control I
            '6.002',  # Circuits and Electronics
        ]
    }

    # Advanced specializations
    SPECIALIZATIONS = {
        'quantum_computing': [
            '8.04',   # Quantum Physics I
            '8.05',   # Quantum Physics II
            '8.06',   # Quantum Physics III
            '6.845',  # Quantum Complexity Theory
            '2.111',  # Quantum Engineering
        ],
        'machine_learning': [
            '6.034',  # Artificial Intelligence
            '6.867',  # Machine Learning
            '6.864',  # Advanced Natural Language Processing
            '9.520',  # Statistical Learning Theory
        ],
        'rocket_science': [
            '16.00',  # Introduction to Aerospace
            '16.07',  # Dynamics
            '16.50',  # Rocket Propulsion
            '16.90',  # Computational Methods
            '16.346', # Astrodynamics
        ],
        'advanced_mathematics': [
            '18.100', # Real Analysis
            '18.701', # Algebra I
            '18.702', # Algebra II
            '18.901', # Topology
            '18.950', # Differential Geometry
        ]
    }

    def __init__(self):
        """Initialize curriculum builder."""
        self.course_catalog = {}
        self.prerequisite_graph = nx.DiGraph()
        self.skill_map = {}
        self.load_course_catalog()

    def load_course_catalog(self):
        """Load complete MIT course catalog."""
        # Create core courses
        self._create_core_courses()

        # Create advanced courses
        self._create_advanced_courses()

        # Build prerequisite graph
        self._build_prerequisite_graph()

        logger.info(f"Loaded {len(self.course_catalog)} courses")

    def _create_core_courses(self):
        """Create core curriculum courses."""
        # Mathematics
        self.course_catalog['18.01'] = Course(
            course_id='18.01',
            title='Single Variable Calculus',
            department='Mathematics',
            level=1,
            credits=12,
            prerequisites=[],
            topics=['Derivatives', 'Integrals', 'Series', 'Differential Equations'],
            skills=['Calculus', 'Problem Solving', 'Mathematical Reasoning'],
            difficulty=0.6
        )

        self.course_catalog['18.02'] = Course(
            course_id='18.02',
            title='Multivariable Calculus',
            department='Mathematics',
            level=2,
            credits=12,
            prerequisites=['18.01'],
            topics=['Partial Derivatives', 'Multiple Integrals', 'Vector Calculus'],
            skills=['Multivariable Calculus', 'Visualization', 'Vector Analysis'],
            difficulty=0.7
        )

        self.course_catalog['18.03'] = Course(
            course_id='18.03',
            title='Differential Equations',
            department='Mathematics',
            level=3,
            credits=12,
            prerequisites=['18.01', '18.02'],
            topics=['ODEs', 'PDEs', 'Laplace Transforms', 'Fourier Series'],
            skills=['Differential Equations', 'Mathematical Modeling'],
            difficulty=0.75
        )

        self.course_catalog['18.06'] = Course(
            course_id='18.06',
            title='Linear Algebra',
            department='Mathematics',
            level=2,
            credits=12,
            prerequisites=['18.01'],
            topics=['Matrices', 'Eigenvalues', 'Vector Spaces', 'Linear Transformations'],
            skills=['Linear Algebra', 'Abstract Thinking', 'Computational Mathematics'],
            difficulty=0.65
        )

        # Physics
        self.course_catalog['8.01'] = Course(
            course_id='8.01',
            title='Classical Mechanics',
            department='Physics',
            level=1,
            credits=12,
            prerequisites=[],
            corequisites=['18.01'],
            topics=['Kinematics', 'Dynamics', 'Energy', 'Momentum'],
            skills=['Physics', 'Problem Solving', 'Experimental Design'],
            difficulty=0.6
        )

        self.course_catalog['8.02'] = Course(
            course_id='8.02',
            title='Electricity and Magnetism',
            department='Physics',
            level=2,
            credits=12,
            prerequisites=['8.01', '18.01'],
            corequisites=['18.02'],
            topics=['Electrostatics', 'Magnetism', "Maxwell's Equations", 'EM Waves'],
            skills=['Electromagnetism', 'Field Theory', 'Mathematical Physics'],
            difficulty=0.7
        )

        # Computer Science
        self.course_catalog['6.0001'] = Course(
            course_id='6.0001',
            title='Introduction to CS and Programming in Python',
            department='Computer Science',
            level=1,
            credits=6,
            prerequisites=[],
            topics=['Python', 'Algorithms', 'Data Structures', 'Computational Thinking'],
            skills=['Programming', 'Python', 'Algorithm Design'],
            difficulty=0.5
        )

        self.course_catalog['6.006'] = Course(
            course_id='6.006',
            title='Introduction to Algorithms',
            department='Computer Science',
            level=3,
            credits=12,
            prerequisites=['6.0001', '6.009'],
            topics=['Sorting', 'Graph Algorithms', 'Dynamic Programming', 'Complexity'],
            skills=['Algorithms', 'Data Structures', 'Complexity Analysis'],
            difficulty=0.8
        )

    def _create_advanced_courses(self):
        """Create advanced specialization courses."""
        # Quantum Computing
        self.course_catalog['8.04'] = Course(
            course_id='8.04',
            title='Quantum Physics I',
            department='Physics',
            level=4,
            credits=12,
            prerequisites=['8.02', '18.03'],
            topics=['Wave Functions', 'Schrödinger Equation', 'Quantum States', 'Measurement'],
            skills=['Quantum Mechanics', 'Mathematical Physics', 'Abstract Reasoning'],
            difficulty=0.85
        )

        self.course_catalog['8.05'] = Course(
            course_id='8.05',
            title='Quantum Physics II',
            department='Physics',
            level=5,
            credits=12,
            prerequisites=['8.04'],
            topics=['Perturbation Theory', 'Scattering', 'Identical Particles'],
            skills=['Advanced Quantum Mechanics', 'Approximation Methods'],
            difficulty=0.9
        )

        # Rocket Science
        self.course_catalog['16.50'] = Course(
            course_id='16.50',
            title='Rocket Propulsion',
            department='Aerospace Engineering',
            level=50,
            credits=12,
            prerequisites=['2.003', '8.01', '18.03'],
            topics=['Combustion', 'Nozzle Design', 'Propellants', 'Trajectory Optimization'],
            skills=['Propulsion', 'Thermodynamics', 'Fluid Dynamics'],
            difficulty=0.8
        )

        self.course_catalog['16.346'] = Course(
            course_id='16.346',
            title='Astrodynamics',
            department='Aerospace Engineering',
            level=46,
            credits=12,
            prerequisites=['16.07', '18.03'],
            topics=['Orbital Mechanics', 'Three-Body Problem', 'Mission Design'],
            skills=['Astrodynamics', 'Numerical Methods', 'Trajectory Planning'],
            difficulty=0.85
        )

        # Machine Learning
        self.course_catalog['6.034'] = Course(
            course_id='6.034',
            title='Artificial Intelligence',
            department='Computer Science',
            level=34,
            credits=12,
            prerequisites=['6.0001', '18.06'],
            topics=['Search', 'Logic', 'Machine Learning', 'Neural Networks'],
            skills=['AI', 'Machine Learning', 'Knowledge Representation'],
            difficulty=0.75
        )

        self.course_catalog['6.867'] = Course(
            course_id='6.867',
            title='Machine Learning',
            department='Computer Science',
            level=67,
            credits=12,
            prerequisites=['6.034', '18.06', '6.041'],
            topics=['Supervised Learning', 'Unsupervised Learning', 'Deep Learning'],
            skills=['Advanced ML', 'Statistical Learning', 'Neural Networks'],
            difficulty=0.85
        )

    def _build_prerequisite_graph(self):
        """Build directed graph of course prerequisites."""
        for course_id, course in self.course_catalog.items():
            self.prerequisite_graph.add_node(course_id, course=course)

            for prereq in course.prerequisites:
                if prereq in self.course_catalog:
                    self.prerequisite_graph.add_edge(prereq, course_id)

    def generate_learning_path(self,
                              goal: str,
                              time_constraint: Optional[int] = None,
                              difficulty_preference: str = 'balanced') -> LearningPath:
        """
        Generate personalized learning path for ECH0.

        Args:
            goal: Learning goal (e.g., 'quantum_computing', 'rocket_science')
            time_constraint: Maximum hours available
            difficulty_preference: 'easy', 'balanced', 'challenging'

        Returns:
            Optimized learning path
        """
        logger.info(f"Generating learning path for goal: {goal}")

        # Get target courses for goal
        if goal in self.SPECIALIZATIONS:
            target_courses = self.SPECIALIZATIONS[goal]
        else:
            target_courses = self._infer_courses_for_goal(goal)

        # Get all prerequisites
        required_courses = self._get_all_prerequisites(target_courses)

        # Add core requirements
        for dept_courses in self.CORE_REQUIREMENTS.values():
            required_courses.update(dept_courses)

        # Order courses by dependency and difficulty
        ordered_courses = self._topological_sort_courses(required_courses)

        # Apply difficulty preference
        ordered_courses = self._apply_difficulty_preference(
            ordered_courses, difficulty_preference
        )

        # Apply time constraint if specified
        if time_constraint:
            ordered_courses = self._apply_time_constraint(
                ordered_courses, time_constraint
            )

        # Calculate metrics
        total_hours = sum(self.course_catalog[c].estimated_hours
                         for c in ordered_courses if c in self.course_catalog)

        estimated_duration = timedelta(hours=total_hours)

        skill_coverage = self._calculate_skill_coverage(ordered_courses)

        difficulty_progression = [
            self.course_catalog[c].difficulty
            for c in ordered_courses if c in self.course_catalog
        ]

        # Create learning path
        path = LearningPath(
            path_id=f"path_{goal}_{datetime.now().strftime('%Y%m%d')}",
            name=f"MIT-Level {goal.replace('_', ' ').title()} Curriculum",
            goal=goal,
            courses=[self.course_catalog[c] for c in ordered_courses
                    if c in self.course_catalog],
            total_hours=total_hours,
            estimated_duration=estimated_duration,
            skill_coverage=skill_coverage,
            difficulty_progression=difficulty_progression
        )

        logger.info(f"Generated path with {len(path.courses)} courses, {total_hours} hours")

        return path

    def _get_all_prerequisites(self, target_courses: List[str]) -> Set[str]:
        """Get all prerequisites recursively."""
        required = set(target_courses)
        to_process = list(target_courses)

        while to_process:
            course_id = to_process.pop()
            if course_id in self.course_catalog:
                course = self.course_catalog[course_id]
                for prereq in course.prerequisites:
                    if prereq not in required:
                        required.add(prereq)
                        to_process.append(prereq)

        return required

    def _topological_sort_courses(self, course_ids: Set[str]) -> List[str]:
        """Sort courses respecting prerequisites."""
        # Create subgraph with only required courses
        subgraph = self.prerequisite_graph.subgraph(
            [c for c in course_ids if c in self.prerequisite_graph]
        )

        # Topological sort
        try:
            sorted_courses = list(nx.topological_sort(subgraph))
        except nx.NetworkXError:
            # Handle cycles
            logger.warning("Cycle detected in prerequisites, using best effort sort")
            sorted_courses = list(course_ids)

        return sorted_courses

    def _apply_difficulty_preference(self,
                                    courses: List[str],
                                    preference: str) -> List[str]:
        """Adjust course ordering based on difficulty preference."""
        if preference == 'easy':
            # Sort by difficulty within each level
            return sorted(courses, key=lambda c: (
                len(self._get_all_prerequisites([c])),
                self.course_catalog.get(c, Course('', '', '', 0, 0)).difficulty
            ))
        elif preference == 'challenging':
            # Include more advanced courses earlier if prerequisites met
            return courses  # Keep topological order but don't simplify
        else:
            # Balanced - default topological sort
            return courses

    def _apply_time_constraint(self,
                              courses: List[str],
                              max_hours: int) -> List[str]:
        """Trim curriculum to fit time constraint."""
        selected = []
        total_hours = 0

        for course_id in courses:
            if course_id in self.course_catalog:
                course_hours = self.course_catalog[course_id].estimated_hours
                if total_hours + course_hours <= max_hours:
                    selected.append(course_id)
                    total_hours += course_hours

        return selected

    def _calculate_skill_coverage(self, courses: List[str]) -> Dict[str, float]:
        """Calculate skill coverage percentage."""
        skill_counts = {}

        for course_id in courses:
            if course_id in self.course_catalog:
                course = self.course_catalog[course_id]
                for skill in course.skills:
                    skill_counts[skill] = skill_counts.get(skill, 0) + 1

        # Normalize to 0-1 scale
        max_count = max(skill_counts.values()) if skill_counts else 1
        return {skill: count/max_count for skill, count in skill_counts.items()}

    def _infer_courses_for_goal(self, goal: str) -> List[str]:
        """Infer relevant courses based on goal keywords."""
        relevant = []
        goal_lower = goal.lower()

        for course_id, course in self.course_catalog.items():
            # Check if goal keywords match course content
            if any(keyword in goal_lower for keyword in [
                topic.lower() for topic in course.topics
            ]):
                relevant.append(course_id)

        return relevant[:10]  # Limit to top 10 most relevant

    def generate_assessment(self, course: Course) -> Dict[str, Any]:
        """
        Generate assessment for a course.

        Args:
            course: Course to assess

        Returns:
            Assessment questions and rubric
        """
        assessment = {
            'course_id': course.course_id,
            'title': f"Assessment for {course.title}",
            'questions': [],
            'rubric': {},
            'time_limit': 180  # 3 hours
        }

        # Generate questions for each topic
        for i, topic in enumerate(course.topics[:5]):  # Max 5 topics
            question = {
                'id': f"q{i+1}",
                'topic': topic,
                'type': 'problem_solving',
                'question': f"Solve a complex problem involving {topic}",
                'points': 20,
                'difficulty': course.difficulty
            }
            assessment['questions'].append(question)

        # Create rubric
        assessment['rubric'] = {
            'excellent': 90,
            'good': 80,
            'satisfactory': 70,
            'needs_improvement': 60
        }

        return assessment

    def track_progress(self,
                      path: LearningPath,
                      completed_courses: List[str]) -> Dict[str, Any]:
        """
        Track ECH0's progress through curriculum.

        Args:
            path: Learning path being followed
            completed_courses: List of completed course IDs

        Returns:
            Progress metrics
        """
        total_courses = len(path.courses)
        completed_count = len([c for c in completed_courses
                              if c in [course.course_id for course in path.courses]])

        progress = {
            'path_id': path.path_id,
            'total_courses': total_courses,
            'completed_courses': completed_count,
            'percentage_complete': (completed_count / total_courses * 100) if total_courses > 0 else 0,
            'hours_completed': sum(
                self.course_catalog[c].estimated_hours
                for c in completed_courses if c in self.course_catalog
            ),
            'hours_remaining': path.total_hours - sum(
                self.course_catalog[c].estimated_hours
                for c in completed_courses if c in self.course_catalog
            ),
            'current_course': self._get_current_course(path, completed_courses),
            'next_courses': self._get_next_courses(path, completed_courses),
            'skills_acquired': self._get_acquired_skills(completed_courses)
        }

        return progress

    def _get_current_course(self,
                           path: LearningPath,
                           completed: List[str]) -> Optional[str]:
        """Get current course in progress."""
        for course in path.courses:
            if course.course_id not in completed:
                # Check if prerequisites are met
                prereqs_met = all(p in completed for p in course.prerequisites)
                if prereqs_met:
                    return course.course_id
        return None

    def _get_next_courses(self,
                         path: LearningPath,
                         completed: List[str],
                         limit: int = 3) -> List[str]:
        """Get next available courses."""
        available = []

        for course in path.courses:
            if course.course_id not in completed:
                prereqs_met = all(p in completed for p in course.prerequisites)
                if prereqs_met:
                    available.append(course.course_id)
                    if len(available) >= limit:
                        break

        return available

    def _get_acquired_skills(self, completed: List[str]) -> List[str]:
        """Get all skills from completed courses."""
        skills = set()

        for course_id in completed:
            if course_id in self.course_catalog:
                skills.update(self.course_catalog[course_id].skills)

        return list(skills)

    def export_curriculum(self, path: LearningPath, output_file: Path):
        """Export curriculum to JSON."""
        data = {
            'path_id': path.path_id,
            'name': path.name,
            'goal': path.goal,
            'total_hours': path.total_hours,
            'estimated_duration': str(path.estimated_duration),
            'courses': [
                {
                    'course_id': c.course_id,
                    'title': c.title,
                    'department': c.department,
                    'level': c.level,
                    'credits': c.credits,
                    'prerequisites': c.prerequisites,
                    'topics': c.topics,
                    'skills': c.skills,
                    'difficulty': c.difficulty,
                    'estimated_hours': c.estimated_hours
                }
                for c in path.courses
            ],
            'skill_coverage': path.skill_coverage,
            'difficulty_progression': path.difficulty_progression
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported curriculum to {output_file}")


def demonstrate_curriculum_builder():
    """Demonstrate curriculum builder capabilities."""
    print("\n=== ECH0 Curriculum Builder Demonstration ===\n")

    # Initialize builder
    builder = MITCurriculumBuilder()

    # Generate different learning paths
    goals = ['quantum_computing', 'rocket_science', 'machine_learning']

    for goal in goals:
        print(f"\n--- Generating {goal.replace('_', ' ').title()} Curriculum ---")

        # Generate path
        path = builder.generate_learning_path(
            goal=goal,
            time_constraint=2000,  # 2000 hours limit
            difficulty_preference='balanced'
        )

        print(f"Path: {path.name}")
        print(f"Total Courses: {len(path.courses)}")
        print(f"Total Hours: {path.total_hours}")
        print(f"Estimated Duration: {path.estimated_duration}")

        # Show first 5 courses
        print("\nFirst 5 Courses:")
        for i, course in enumerate(path.courses[:5]):
            print(f"  {i+1}. {course.course_id}: {course.title}")

        # Track progress (simulate)
        completed = [path.courses[0].course_id] if path.courses else []
        progress = builder.track_progress(path, completed)

        print(f"\nProgress: {progress['percentage_complete']:.1f}% complete")
        print(f"Current Course: {progress['current_course']}")
        print(f"Next Available: {', '.join(progress['next_courses'])}")

        # Export curriculum
        output_file = Path(f"/tmp/curriculum_{goal}.json")
        builder.export_curriculum(path, output_file)
        print(f"Exported to: {output_file}")


if __name__ == "__main__":
    demonstrate_curriculum_builder()