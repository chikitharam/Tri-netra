# ============================================================
# TRINETRA MAIN ENTRY POINT
# ============================================================
# This file serves as the main entry point for the application.
#
# Flags:
#   --test               Run the community-classifier tests
#   --dashboard          Start the Flask dashboard
#   --process <id>       Process a specific threat
#   --process <id> --force   Reprocess even if already processed
#   --all                Process every unprocessed threat
#   --seed-users         Create the Module 6 demo users in Firebase
# ============================================================

import sys
import argparse


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Trinetra Threat Intelligence Engine"
    )
    parser.add_argument("--test", action="store_true", help="Run tests")
    parser.add_argument("--dashboard", action="store_true", help="Start dashboard")
    parser.add_argument("--process", help="Process a specific threat ID")
    parser.add_argument("--all", action="store_true", help="Process all threats")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Reprocess even if already marked processed (use with --process)"
    )
    parser.add_argument(
        "--seed-users",
        action="store_true",
        help="Create the Module 6 demo users in Firebase"
    )

    args = parser.parse_args()

    if args.test:
        print("Running tests...")
        from test_community_classifier import main as test_main
        test_main()

    elif args.seed_users:
        print("Seeding Module 6 demo users...")
        from seed_users import main as seed_main
        seed_main()

    elif args.dashboard:
        print("Starting dashboard...")
        from dashboard import app
        app.run(host="127.0.0.1", port=5001, debug=True)

    elif args.process:
        print(f"Processing threat: {args.process}")
        from ai_engine import process_threat
        result = process_threat(args.process, force=args.force)
        print(result)

    elif args.all:
        print("Processing all threats...")
        from ai_engine import __main__

    else:
        print("=" * 50)
        print("🛡️ TRINETRA THREAT INTELLIGENCE ENGINE")
        print("=" * 50)
        print()
        print("Usage:")
        print("  python main.py --test                        Run tests")
        print("  python main.py --dashboard                   Start dashboard")
        print("  python main.py --process <id>                Process a specific threat")
        print("  python main.py --process <id> --force        Reprocess a threat")
        print("  python main.py --all                         Process all threats")
        print("  python main.py --seed-users                  Create demo users")
        print()
        print("Module 6 quick start:")
        print("  python main.py --seed-users")
        print("  python main.py --dashboard")
        print("  → open http://127.0.0.1:5001/login")
        print()
        print("Examples:")
        print("  python main.py --test")
        print("  python main.py --dashboard")
        print("  python main.py --process t1")
        print("  python main.py --process t1 --force")
        print("  python main.py --all")
        print("=" * 50)


if __name__ == "__main__":
    main()