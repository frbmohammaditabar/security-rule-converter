import os
import magic
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

class FileProcessor:
    def __init__(self):
        self.mime = magic.Magic(mime=True)
    
    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file and extract features for rule generation"""
        try:
            file_stats = self._get_file_info(file_path)
            content_analysis = self._analyze_content(file_path)
            
            return {
                **file_stats,
                **content_analysis,
                'file_type': self._detect_file_type(file_path)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return {}
    
    def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get basic file information"""
        stat = file_path.stat()
        return {
            'file_size': stat.st_size,
            'modified_time': stat.st_mtime,
            'file_name': file_path.name,
            'file_extension': file_path.suffix.lower()
        }
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type using magic"""
        try:
            return self.mime.from_file(str(file_path))
        except:
            return "unknown"
    
    def _analyze_content(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file content for patterns"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB for analysis
            
            return {
                'has_text_patterns': self._has_text_patterns(content),
                'has_binary_patterns': self._has_binary_patterns(content),
                'potential_indicators': self._find_potential_indicators(content)
            }
            
        except Exception as e:
            logger.warning(f"Could not analyze content of {file_path}: {e}")
            return {}
    
    def _has_text_patterns(self, content: bytes) -> bool:
        """Check if content contains text patterns"""
        try:
            text_content = content.decode('utf-8', errors='ignore')
            return any(c.isprintable() for c in text_content[:100])
        except:
            return False
    
    def _has_binary_patterns(self, content: bytes) -> bool:
        """Check for binary patterns"""
        return any(b > 127 for b in content[:100])
    
    def _find_potential_indicators(self, content: bytes) -> list:
        """Find potential IOCs in content"""
        indicators = []
        text_content = content.decode('utf-8', errors='ignore')
        
        # Simple pattern matching (expand based on requirements)
        patterns = [
            ('http://', 'URL'),
            ('https://', 'URL'),
            ('.exe', 'Executable'),
            ('.dll', 'Library'),
            ('malware', 'Malware reference'),
            ('virus', 'Virus reference')
        ]
        
        for pattern, indicator_type in patterns:
            if pattern in text_content.lower():
                indicators.append(f"{indicator_type}: {pattern}")
        
        return indicators
