from security_log_loader import SecurityLogLoader
from security_log_analyzer import SecurityLogAnalyzer
from report_exporter import ReportExporter


def main() -> None:
    """Run the security log analysis pipeline."""

    input_path = "security_logs.json"
    output_path = "report.json"

    try:
       
        loader = SecurityLogLoader()
        events = loader.load_security_logs(input_path)

        
        analyzer = SecurityLogAnalyzer()
        report = analyzer.analyze_security_logs(events)

       
        exporter = ReportExporter()
        exporter.export_report(report, output_path)

    except (OSError, TypeError, ValueError) as error:
        print(f"❌ Security analysis failed: {error}")
        return

    
    print("✅ Security analysis completed successfully!")
    print(f"Report exported to: {output_path}")
    print("-" * 40)

    for key, value in report.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
