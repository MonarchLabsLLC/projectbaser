#!/usr/bin/env python3
"""
Cloudflare SSL Mode Checker and Updater (Optimized)
Lists all domains on Flexible SSL and can update them to Full mode.
Uses concurrent requests for faster processing.
"""

import requests
import json
import concurrent.futures
import time
import sys

# Cloudflare Credentials
CLOUDFLARE_EMAIL = "housni@groovedigital.com"
CLOUDFLARE_TOKEN = "BXDi2zlywTaXCL4vswMZHq4SG7TvsW8M7sT8mUTL"
CLOUDFLARE_ACCOUNT_ID = "ac0f8f0852a759739d1b38341e14f51a"

# API Headers (using Bearer token format for API Tokens)
headers = {
    "Authorization": f"Bearer {CLOUDFLARE_TOKEN}",
    "Content-Type": "application/json"
}

# Rate limiting: Cloudflare allows 1200 requests per 5 minutes
MAX_WORKERS = 20  # Concurrent requests

def get_all_zones():
    """Fetch all zones (domains) from Cloudflare account."""
    zones = []
    page = 1
    per_page = 50

    print("Fetching all domains from Cloudflare...")

    while True:
        url = f"https://api.cloudflare.com/client/v4/zones?page={page}&per_page={per_page}"
        response = requests.get(url, headers=headers)
        data = response.json()

        if not data.get("success"):
            print(f"Error fetching zones: {data.get('errors', 'Unknown error')}")
            return []

        zones.extend(data.get("result", []))

        result_info = data.get("result_info", {})
        total_pages = result_info.get("total_pages", 1)
        total_count = result_info.get("total_count", 0)

        print(f"  Fetched page {page}/{total_pages} ({len(zones)}/{total_count} domains)")

        if page >= total_pages:
            break
        page += 1

    return zones

def get_ssl_setting(zone):
    """Get SSL setting for a specific zone."""
    zone_id = zone["id"]
    zone_name = zone["name"]

    try:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl"
        response = requests.get(url, headers=headers, timeout=30)
        data = response.json()

        if data.get("success"):
            ssl_mode = data.get("result", {}).get("value", "unknown")
            return {
                "id": zone_id,
                "name": zone_name,
                "ssl_mode": ssl_mode
            }
    except Exception as e:
        pass

    return {
        "id": zone_id,
        "name": zone_name,
        "ssl_mode": "error"
    }

def set_ssl_mode(zone_id, zone_name, mode="full"):
    """Set SSL mode for a specific zone."""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl"
    payload = {"value": mode}

    try:
        response = requests.patch(url, headers=headers, json=payload, timeout=30)
        data = response.json()

        if data.get("success"):
            return True, f"Successfully updated {zone_name} to {mode}"
        return False, f"Failed to update {zone_name}: {data.get('errors', 'Unknown error')}"
    except Exception as e:
        return False, f"Error updating {zone_name}: {str(e)}"

def main():
    print("=" * 60)
    print("Cloudflare SSL Mode Checker (Optimized)")
    print("=" * 60)
    print()

    zones = get_all_zones()

    if not zones:
        print("No zones found or error occurred.")
        return

    print(f"\nTotal domains: {len(zones)}")
    print(f"Checking SSL settings with {MAX_WORKERS} concurrent workers...")
    print("-" * 60)

    flexible_zones = []
    checked = 0
    start_time = time.time()

    # Use ThreadPoolExecutor for concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_zone = {executor.submit(get_ssl_setting, zone): zone for zone in zones}

        for future in concurrent.futures.as_completed(future_to_zone):
            result = future.result()
            checked += 1

            if result["ssl_mode"] == "flexible":
                flexible_zones.append({
                    "id": result["id"],
                    "name": result["name"]
                })
                print(f"[{checked}/{len(zones)}] FLEXIBLE: {result['name']}")

            # Progress update every 500 domains
            if checked % 500 == 0:
                elapsed = time.time() - start_time
                rate = checked / elapsed
                remaining = (len(zones) - checked) / rate if rate > 0 else 0
                print(f"  ... Progress: {checked}/{len(zones)} ({elapsed:.1f}s elapsed, ~{remaining:.0f}s remaining)")

    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"\nCompleted in {elapsed:.1f} seconds")
    print(f"Total domains checked: {len(zones)}")
    print(f"Domains on FLEXIBLE SSL: {len(flexible_zones)}")

    if flexible_zones:
        print("\n" + "=" * 60)
        print("DOMAINS ON FLEXIBLE SSL (need to be changed to Full):")
        print("=" * 60)
        for i, zone in enumerate(flexible_zones, 1):
            print(f"  {i}. {zone['name']}")

        # Save flexible zones to file for the update script
        with open("/var/www/html/projectbaser/flexible_zones.json", "w") as f:
            json.dump(flexible_zones, f, indent=2)
        print(f"\nFlexible zones saved to: flexible_zones.json")
        print("\nRun with --update flag to change these to Full SSL mode.")
    else:
        print("\nAll domains are already on Full or Strict SSL mode!")

def update_flexible_to_full():
    """Update all flexible zones to full SSL mode."""
    try:
        with open("/var/www/html/projectbaser/flexible_zones.json", "r") as f:
            flexible_zones = json.load(f)
    except FileNotFoundError:
        print("No flexible_zones.json found. Run the script without --update first.")
        return

    if not flexible_zones:
        print("No flexible zones to update.")
        return

    print("=" * 60)
    print("Updating Flexible SSL zones to Full mode")
    print("=" * 60)
    print(f"Total zones to update: {len(flexible_zones)}")
    print()

    success_count = 0
    fail_count = 0

    for i, zone in enumerate(flexible_zones, 1):
        success, message = set_ssl_mode(zone["id"], zone["name"], "full")
        status = "OK" if success else "FAIL"
        print(f"[{i}/{len(flexible_zones)}] {status}: {zone['name']}")

        if success:
            success_count += 1
        else:
            fail_count += 1

        # Small delay to avoid rate limiting
        time.sleep(0.1)

    print("\n" + "=" * 60)
    print(f"Update complete!")
    print(f"  Success: {success_count}")
    print(f"  Failed: {fail_count}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--update":
        update_flexible_to_full()
    else:
        main()
