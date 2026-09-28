"""Convert the archived official dataset snapshot to a small, auditable CSV seed.

Source: data.mos.ru/opendata/893, version 7.27 (04.10.2021), mirrored on
23.10.2021 by DataCrafter. Run from the project root after installing requirements.
"""
import csv
import gzip
import io
import json
import zipfile
from pathlib import Path

from bson import decode_all

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "sportsgrounds_2021_source.zip"
TARGET = ROOT / "data" / "venues_seed.csv"


def main():
    with zipfile.ZipFile(SOURCE) as source:
        metadata = json.loads(source.read("meta.json"))
        if metadata["Id"] != 893:
            raise ValueError("Unexpected dataset identifier")
        documents = decode_all(gzip.decompress(source.read("data.bson.gz")))

    fields = ("source_id", "name", "facility_name", "area", "address", "lat", "lon",
              "opening_hours", "usage_period", "paid", "paid_comment", "website",
              "phone", "accessibility")
    seen = set()
    with TARGET.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for item in documents:
            identifier = item["global_id"]
            if identifier in seen:
                raise ValueError(f"Duplicate global_id {identifier}")
            seen.add(identifier)
            lon, lat = item["geoData"]["coordinates"][:2]
            if not (36 <= lon <= 39 and 54 <= lat <= 57):
                raise ValueError(f"Invalid coordinates {identifier}")
            comment = (item.get("PaidComments") or "").strip()
            # The source also uses placeholders or repeats the Paid field here.
            if comment.casefold() in {"0", "00", "нет", "нет данных", "бесплатно",
                                       "без оплаты", "платно"}:
                comment = ""
            writer.writerow(dict(source_id=identifier, name=item["NameSummer"],
                facility_name=item["ObjectName"], area=item["District"],
                address=item["Address"], lat=lat, lon=lon,
                opening_hours=json.dumps(item["WorkingHoursSummer"],ensure_ascii=False),
                usage_period=item["UsagePeriodSummer"], paid=item["Paid"],
                paid_comment=comment, website=(item.get("WebSite") or "").strip(),
                phone=(item.get("HelpPhone") or "").strip(),
                accessibility=item.get("DisabilityFriendly") or ""))
    print(f"{len(seen)} unique venues written to {TARGET}")


if __name__ == "__main__":
    main()
