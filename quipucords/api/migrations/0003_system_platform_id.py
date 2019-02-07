# Generated by Django 2.1.5 on 2019-02-05 23:49

from django.db import migrations, models
import json
import uuid

# pylint: disable=no-name-in-module,import-error
from distutils.version import LooseVersion

from api.deployments_report.serializer import SystemFingerprintSerializer

CANONICAL_FACTS = ['bios_uuid', 'etc_machine_id', 'insights_client_id',
                   'ip_addresses', 'mac_addresses',
                   'subscription_manager_id', 'vm_uuid']

def add_system_platform_id(apps, schema_editor):
    # Get old deployments reports
    DeploymentsReport = apps.get_model('api', 'DeploymentsReport')
    print('Migrating deployments reports')
    count = 0
    for report in DeploymentsReport.objects.all():
        cached_fingerprints = []
        insights_hosts = {}
        if LooseVersion(report.report_version) < LooseVersion('0.0.47'):
            print('Migrating deployments report %s' % report.id)
            try:
                for system_fingerprint in report.system_fingerprints.all():
                    found_canonical_facts = False
                    count += 1
                    if count % 100 == 0:
                        print('%d fingerprints migrated' % count)
                    # Generate unique id per system
                    system_fingerprint.system_platform_id = uuid.uuid4()
                    system_fingerprint.save()

                    # Serialize
                    serializer = SystemFingerprintSerializer(system_fingerprint)
                    # json dumps/loads changes type of dictionary
                    # removes massive memory growth for cached_fingerprints
                    cached_fingerprints.append(json.loads(json.dumps(serializer.data)))
                    # Check if fingerprint has canonical facts
                    for fact in CANONICAL_FACTS:
                        if has_attr(system_fingerprint, fact):
                            if system_fingerprint.fact:
                                found_canonical_facts = True
                            break
                    # If canonical facts, add it to the insights_hosts dict
                    if found_canonical_facts:
                        insights_id = system_fingerprint.system_platform_id
                        insights_hosts[insights_id] = \
                            json.dumps(json.loads(serializer.data).pop('system_platform_id'))
                report.cached_fingerprints = json.dumps(cached_fingerprints)
                report.cached_insights = json.dumps(insights_hosts)
                report.cached_csv = None
                report.save()
            except Exception:
                print('Failed to migrate report %s.  Cannot be used with insights.' % report.id)

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_insights_reports'),
    ]

    operations = [
        migrations.RenameField(
            model_name='deploymentsreport',
            old_name='cached_json',
            new_name='cached_fingerprints',
        ),
        migrations.AddField(
            model_name='deploymentsreport',
            name='cached_insights',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='systemfingerprint',
            name='system_platform_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.RunPython(add_system_platform_id),
    ]
