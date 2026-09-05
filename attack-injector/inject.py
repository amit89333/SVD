import argparse
import sys
import os

from attack_dos import run_dos_attack
from attack_fuzzing import run_fuzzing_attack
from attack_spoofing import run_spoofing_attack
from attack_replay import run_replay_attack

def main():
    parser = argparse.ArgumentParser(description="SDV CAN Bus Attack Injector CLI")
    parser.add_argument("--attack", type=str, required=True, choices=["dos", "fuzzing", "spoofing", "replay"], help="Type of attack to inject")
    parser.add_argument("--duration", type=float, default=5.0, help="Attack duration in seconds")
    parser.add_argument("--target", type=str, default="vehicle-1", help="Target vehicle identifier")
    
    args = parser.parse_args()
    print(f"=== SDV Attack Injector: Targeting {args.target} ===")
    
    if args.attack == "dos":
        run_dos_attack(duration=args.duration)
    elif args.attack == "fuzzing":
        run_fuzzing_attack(duration=args.duration)
    elif args.attack == "spoofing":
        run_spoofing_attack(duration=args.duration)
    elif args.attack == "replay":
        run_replay_attack(duration=args.duration)

if __name__ == "__main__":
    main()
