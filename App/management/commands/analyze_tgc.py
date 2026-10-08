import json
from django.core.management.base import BaseCommand
from App.models import ThreatProfile
from tqdm import tqdm

class Command(BaseCommand):
    help = "Import TGC efficiently for very large datasets"

    def add_arguments(self, parser):
        parser.add_argument(
            "--file",
            default="tgc.json",
            help="Path to tgc.json file"
        )

    def handle(self, *args, **options):
        path = options["file"]

        # Load JSON
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        created_count, updated_count = 0, 0
        new_entries = []
        update_entries = []

        # Load existing entries once
        existing_qs = ThreatProfile.objects.filter(threat_focus="actors")
        existing_dict = {tp.name: tp for tp in existing_qs}

        # Flatten all groups and subgroups into a single list
        all_groups = []

        def flatten(group, parent_name=None):
            name = group.get("Name") or "Unknown"
            country = group.get("Country") or "Unknown"
            observed = group.get("Observed") or ""
            all_groups.append({
                "name": name.strip(),
                "region": country.strip(),
                "description": observed.strip(),
                "parent_group": parent_name
            })
            for sub in group.get("Subgroups") or []:
                flatten(sub, parent_name=name.strip())

        for entry in data:
            flatten(entry)

        # Process flattened list with progress bar
        for g in tqdm(all_groups, desc="Processing groups", unit="group"):
            name_field = g["name"]
            if name_field in existing_dict:
                obj = existing_dict[name_field]
                obj.region = g["region"]
                obj.description = g["description"]
                obj.source = "TGC"
                obj.parent_group = g["parent_group"]
                update_entries.append(obj)
            else:
                new_entries.append(
                    ThreatProfile(
                        name=name_field,
                        threat_focus="actors",
                        region=g["region"],
                        description=g["description"],
                        source="TGC",
                        parent_group=g["parent_group"]
                    )
                )

        # Bulk create and update in chunks
        batch_size = 1000
        for i in range(0, len(new_entries), batch_size):
            ThreatProfile.objects.bulk_create(new_entries[i:i+batch_size], batch_size=batch_size)
            created_count += len(new_entries[i:i+batch_size])

        if update_entries:
            ThreatProfile.objects.bulk_update(
                update_entries,
                fields=["region", "description", "source", "parent_group"],
                batch_size=batch_size
            )
            updated_count += len(update_entries)

        self.stdout.write(self.style.SUCCESS(
            f"TGC import complete: {created_count} created, {updated_count} updated."
        ))
