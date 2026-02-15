from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, TypeVar, Type
import json

T = TypeVar("T")


# Custom exception for parsing errors with context
class CVEParseError(Exception):
    """Raised when CVE JSON parsing fails with context about what went wrong"""

    pass


# Utility function for safe parsing with error context
def _parse_nested(
    cls: Type[T], data: Optional[Dict[str, Any]], context: str
) -> Optional[T]:
    """
    Safely parse nested dataclass from dictionary data.
    Returns None if data is None, otherwise attempts to create instance.
    Provides context in error messages about where parsing failed.
    """
    if data is None:
        return None

    try:
        # Get the field names this dataclass expects
        field_names = {f.name for f in cls.__dataclass_fields__.values()}
        # Filter to only include fields the dataclass knows about
        filtered = {k: v for k, v in data.items() if k in field_names}
        return cls(**filtered)
    except (TypeError, KeyError) as e:
        raise CVEParseError(f"Failed to parse {cls.__name__} in {context}: {e}") from e


def _parse_nested_list(
    cls: Type[T], data: Optional[List[Dict[str, Any]]], context: str
) -> List[T]:
    """
    Parse a list of nested dataclass instances.
    Returns empty list if data is None or empty.
    Provides indexed context in error messages.
    """
    if not data:
        return []

    result = []
    for idx, item in enumerate(data):
        try:
            parsed = _parse_nested(cls, item, f"{context}[{idx}]")
            if parsed:
                result.append(parsed)
        except CVEParseError:
            # Re-raise with more context
            raise
        except Exception as e:
            raise CVEParseError(
                f"Unexpected error parsing {cls.__name__} at {context}[{idx}]: {e}"
            ) from e

    return result


#======================================================
# DATA MODELS 
#======================================================
@dataclass
class CWEDescription:
    """Represents a CWE (Common Weakness Enumeration) classification"""

    cweId: str | None = None
    lang: str | None = None
    description: str | None = None
    type: str | None = None


@dataclass
class ProblemType:
    """Groups related CWE descriptions together"""

    descriptions: List[CWEDescription] = field(default_factory=list)


@dataclass
class CVSSMetric:
    """
    CVSS (Common Vulnerability Scoring System) v4.0 metrics.
    These scores quantify the severity and characteristics of a vulnerability.
    """

    baseScore: float
    baseSeverity: str
    vectorString: str
    version: str

    attackVector: str | None = None
    attackComplexity: str | None = None
    attackRequirements: str | None = None
    privilegesRequired: str | None = None
    userInteraction: str | None = None
    vulnConfidentialityImpact: str | None = None
    vulnIntegrityImpact: str | None = None
    vulnAvailabilityImpact: str | None = None
    subConfidentialityImpact: str | None = None
    subIntegrityImpact: str | None = None
    subAvailabilityImpact: str | None = None


@dataclass
class Metric:
    """Wrapper for CVSS metric, allows for multiple metric types in the future"""

    cvssV4_0: Optional[CVSSMetric] = None


@dataclass
class Reference:
    """External reference to documentation, advisories, or fixes"""

    url: str
    name: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class Version:
    """Version information for affected software"""

    version: str
    status: str


@dataclass
class AffectedProduct:
    """Information about a product affected by this vulnerability"""

    vendor: str
    product: str
    versions: List[Version] = field(default_factory=list)


@dataclass
class Description:
    """Human-readable description of the vulnerability"""

    lang: str
    value: str


@dataclass
class Source:
    """Information about how the vulnerability was discovered"""

    advisory: Optional[str] = None
    discovery: Optional[str] = None


@dataclass
class ProviderMetadata:
    """Metadata about the organization providing this CVE information"""

    orgId: str
    shortName: str
    dateUpdated: str


@dataclass
class CNAContainer:
    """
    CNA (CVE Numbering Authority) container with the primary vulnerability data.
    This is the core information about the vulnerability from the assigning authority.
    """

    title: str
    descriptions: List[Description] = field(default_factory=list)
    problemTypes: List[ProblemType] = field(default_factory=list)
    metrics: List[Metric] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)
    affected: List[AffectedProduct] = field(default_factory=list)
    providerMetadata: Optional[ProviderMetadata] = None
    source: Optional[Source] = None


@dataclass
class SSVCOption:
    """Stakeholder-Specific Vulnerability Categorization option"""

    # The keys are dynamic (e.g., "Exploitation", "Automatable")
    # We'll store this as a single key-value pair per option
    key: str
    value: str


@dataclass
class SSVCContent:
    """SSVC decision tree content used by CISA for prioritization"""

    timestamp: str
    id: str
    role: str
    version: str
    options: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class OtherMetric:
    """Container for alternative metric systems like SSVC"""

    type: str
    content: Optional[Dict[str, Any]] = None


@dataclass
class ADPContainer:
    """
    ADP (Authorized Data Publisher) container with additional enrichment data.
    Organizations like CISA add their own analysis and metadata here.
    """

    title: Optional[str] = None
    references: List[Reference] = field(default_factory=list)
    metrics: List[Dict[str, Any]] = field(default_factory=list)
    providerMetadata: Optional[ProviderMetadata] = None


@dataclass
class Containers:
    """
    Top-level containers holding vulnerability information.
    CNA contains primary data, ADP contains additional publisher enrichments.
    """

    cna: Optional[CNAContainer] = None
    adp: List[ADPContainer] = field(default_factory=list)


@dataclass
class CVEMetadata:
    """Administrative metadata about the CVE record itself"""

    cveId: str
    assignerOrgId: str
    state: str
    assignerShortName: str
    dateReserved: str
    datePublished: str
    dateUpdated: str


@dataclass
class CVERecord:
    """
    Top-level CVE record following the CVE JSON 5.2 schema.
    This represents a complete vulnerability disclosure record.
    """

    dataType: str
    dataVersion: str
    cveMetadata: CVEMetadata
    containers: Containers

    def validate(self) -> None:
        """
        Perform semantic validation beyond structural parsing.
        Checks business rules and data consistency.
        """
        if self.dataType != "CVE_RECORD":
            raise CVEParseError(
                f"Invalid dataType: expected 'CVE_RECORD', got '{self.dataType}'"
            )

        if not self.cveMetadata.cveId.startswith("CVE-"):
            raise CVEParseError(f"Invalid CVE ID format: {self.cveMetadata.cveId}")

        # Validate state is one of the allowed values
        valid_states = {"PUBLISHED", "REJECTED", "RESERVED"}
        if self.cveMetadata.state not in valid_states:
            raise CVEParseError(
                f"Invalid state '{self.cveMetadata.state}', "
                f"must be one of {valid_states}"
            )

#======================================================
# CVE RECORD PARSER 
#======================================================
def parse_cve_record(json_data: Dict[str, Any]) -> CVERecord:
    """
    Parse a CVE record from dictionary data with full error handling.

    This function carefully handles the nested structure and provides
    clear error messages about what failed and where.
    """
    try:
        # Parse CVE metadata first (required)
        metadata_dict = json_data.get("cveMetadata")
        if not metadata_dict:
            raise CVEParseError("Missing required 'cveMetadata' field")

        cve_metadata = _parse_nested(CVEMetadata, metadata_dict, "cveMetadata")
        if not cve_metadata:
            raise CVEParseError("Failed to parse cveMetadata")

        # Parse containers (required)
        containers_dict = json_data.get("containers")
        if not containers_dict:
            raise CVEParseError("Missing required 'containers' field")

        # Parse CNA container
        cna_dict = containers_dict.get("cna")
        cna_container = None
        if cna_dict:
            cna_container = parse_cna_container(cna_dict)

        # Parse ADP containers (optional array)
        adp_list = containers_dict.get("adp", [])
        adp_containers = _parse_nested_list(ADPContainer, adp_list, "containers.adp")

        containers = Containers(cna=cna_container, adp=adp_containers)

        # Create the CVE record
        record = CVERecord(
            dataType=json_data.get("dataType", ""),
            dataVersion=json_data.get("dataVersion", ""),
            cveMetadata=cve_metadata,
            containers=containers,
        )

        # Perform validation
        record.validate()

        return record

    except CVEParseError:
        # Re-raise our custom errors as-is
        raise
    except Exception as e:
        # Wrap unexpected errors with context
        raise CVEParseError(f"Unexpected error parsing CVE record: {e}") from e


#======================================================
# CNA PARSER
#======================================================
def parse_cna_container(data: Dict[str, Any]) -> CNAContainer:
    """Parse the CNA container with all its nested complexity"""

    # Parse descriptions
    descriptions_data = data.get("descriptions", [])
    descriptions = _parse_nested_list(
        Description, descriptions_data, "cna.descriptions"
    )

    # Parse problem types with nested CWE descriptions
    problem_types_data = data.get("problemTypes", [])
    problem_types = []
    for idx, pt_data in enumerate(problem_types_data):
        cwe_descs_data = pt_data.get("descriptions", [])
        cwe_descriptions = _parse_nested_list(
            CWEDescription, cwe_descs_data, f"cna.problemTypes[{idx}].descriptions"
        )
        problem_types.append(ProblemType(descriptions=cwe_descriptions))

    # Parse metrics (complex nested structure)
    metrics_data = data.get("metrics", [])
    metrics = []
    for idx, metric_data in enumerate(metrics_data):
        cvss_data = metric_data.get("cvssV4_0")
        if cvss_data:
            cvss = _parse_nested(CVSSMetric, cvss_data, f"cna.metrics[{idx}].cvssV4_0")
            metrics.append(Metric(cvssV4_0=cvss))

    # Parse references
    references_data = data.get("references", [])
    references = _parse_nested_list(Reference, references_data, "cna.references")

    # Parse affected products with their versions
    affected_data = data.get("affected", [])
    affected = []
    for idx, affected_item in enumerate(affected_data):
        versions_data = affected_item.get("versions", [])
        versions = _parse_nested_list(
            Version, versions_data, f"cna.affected[{idx}].versions"
        )

        affected_product = AffectedProduct(
            vendor=affected_item.get("vendor", ""),
            product=affected_item.get("product", ""),
            versions=versions,
        )
        affected.append(affected_product)

    # Parse provider metadata
    provider_data = data.get("providerMetadata")
    provider_metadata = _parse_nested(
        ProviderMetadata, provider_data, "cna.providerMetadata"
    )

    # Parse source
    source_data = data.get("source")
    source = _parse_nested(Source, source_data, "cna.source")

    return CNAContainer(
        title=data.get("title", ""),
        descriptions=descriptions,
        problemTypes=problem_types,
        metrics=metrics,
        references=references,
        affected=affected,
        providerMetadata=provider_metadata,
        source=source,
    )



#======================================================
# FILE LOADER 
#======================================================
def load_cve_from_file(filepath: str) -> CVERecord:
    """
    Load and parse a CVE record from a JSON file.

    Args:
        filepath: Path to the JSON file

    Returns:
        Parsed and validated CVE record

    Raises:
        CVEParseError: If file reading or parsing fails
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            json_data = json.load(f)
    except FileNotFoundError:
        raise CVEParseError(f"CVE file not found: {filepath}")
    except json.JSONDecodeError as e:
        raise CVEParseError(
            f"Invalid JSON in {filepath} at line {e.lineno}, column {e.colno}: {e.msg}"
        ) from e
    except Exception as e:
        raise CVEParseError(f"Error reading {filepath}: {e}") from e

    return parse_cve_record(json_data)


def load_cve_from_string(json_string: str) -> CVERecord:
    """
    Load and parse a CVE record from a JSON string.

    Args:
        json_string: JSON string containing CVE data

    Returns:
        Parsed and validated CVE record

    Raises:
        CVEParseError: If parsing fails
    """
    try:
        json_data = json.loads(json_string)
    except json.JSONDecodeError as e:
        raise CVEParseError(
            f"Invalid JSON at line {e.lineno}, column {e.colno}: {e.msg}"
        ) from e

    return parse_cve_record(json_data)


# Convenience function for converting back to JSON
def cve_to_dict(record: CVERecord) -> Dict[str, Any]:
    """
    Convert a CVE record back to dictionary format for JSON serialization.
    Uses asdict but you could customize this for specific serialization needs.
    """
    from dataclasses import asdict

    return asdict(record)


if __name__ == "__main__":

    _DIR = Path.cwd().parent / "cvelistv5" / "cves" / "2022"

    try:
        json_files = list(_DIR.rglob('*.json'))
    except Exception as e:
        raise FileCleanupError(f"Failed to list files: {e}") 
    try:
        # Parse the CVE record
        cve = load_cve_from_file(_TEST_DATA_PATH)

        # structured data with full type safety
        print(f"CVE ID: {cve.cveMetadata.cveId}")
        print(f"State: {cve.cveMetadata.state}")

        if cve.containers.cna:
            print(f"Title: {cve.containers.cna.title}")

            # Access CVSS score if available
            if cve.containers.cna.metrics:
                first_metric = cve.containers.cna.metrics[0]
                if first_metric.cvssV4_0:
                    print(f"CVSS Base Score: {first_metric.cvssV4_0.baseScore}")
                    print(f"Severity: {first_metric.cvssV4_0.baseSeverity}")

            # List affected products
            for product in cve.containers.cna.affected:
                print(f"Affected: {product.vendor} {product.product}")
                for version in product.versions:
                    print(f"  Version: {version.version} ({version.status})")

        # Convert back to dict for serialization
        as_dict = cve_to_dict(cve)

    except CVEParseError as e:
        print(f"Failed to parse CVE: {e}")
