import json

class ReportExporter:
 def export_report(self ,report: dict, file_path: str) -> None:
    """Serialize and export a security report to JSON."""

   
    try:
        json_data = json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
            allow_nan=False
        )

    except (TypeError, ValueError) as error:
        raise ValueError(
            f"Failed to serialize report: {error}"
        ) from error

   
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(json_data)

    except OSError as error:
        raise OSError(
            f"Failed to export report to '{file_path}': {error}"
        ) from error
