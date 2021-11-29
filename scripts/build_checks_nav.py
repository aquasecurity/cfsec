#!/usr/bin/env python3

import os
import yaml


class PrettyDumper(yaml.SafeDumper):
    def write_line_break(self, data=None):
        super().write_line_break(data)

        if len(self.indents) == 1:
            super().write_line_break()


checks = []


for service in sorted(os.listdir(f'./docs/checks/')):
    service_checks = []
    if service == 'home.md':
        services.append(
            {provider: f'checks/{service}/home.md'})
        continue

    for check in sorted(os.listdir(f'./docs/checks/{service}')):
        check_name = check.replace('.md', '')
        service_checks.append(
            {check_name: f'checks/{service}/{check}'})
    checks.append({service: service_checks})


with open('mkdocs.yml', 'r') as fr:
    mkdocs_file = yaml.safe_load(fr)

nav_block = mkdocs_file.get('nav', [])
for sect in nav_block:
    for i in sect:
        if i == 'Checks':
            nav_block.remove(sect)

nav_block.append({'Checks': checks})

mkdocs_file['nav'] = nav_block


with open('mkdocs.yml', 'w') as fw:
    yaml.dump(mkdocs_file, fw, Dumper=PrettyDumper, sort_keys=False)