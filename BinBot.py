import sys
import yara
from rich.live import Live
from time import sleep
from rich import print
import collectors
from classes import *
import json
from os import path, listdir
from concurrent.futures import ThreadPoolExecutor

console = Console()
testvars = json.load(open("config.json"))

def load_config(filepath):
    configpath = path.join(sys.path[0], filepath)
    if path.isfile(configpath):
        vars_dict = json.load(open(configpath))
        if vars_dict['yara_scanning']:
            search_rules = {f.split('.')[0]: path.join(f'{sys.path[0]}/yara_rules/general_rules/', f) for f in
                            listdir(f'{sys.path[0]}/yara_rules/general_rules/') if
                            path.isfile(path.join(f'{sys.path[0]}/yara_rules/general_rules/', f)) and f.endswith(
                                ".yar") or f.endswith(".yara")}
            binary_rules = {f.split('.')[0]: path.join(f'{sys.path[0]}/yara_rules/binary_rules/', f) for f in
                            listdir(f'{sys.path[0]}/yara_rules/binary_rules/') if
                            path.isfile(path.join(f'{sys.path[0]}/yara_rules/binary_rules/', f)) and f.endswith(
                                ".yar") or f.endswith(".yara")}
            vars_dict['search_rules'] = yara.compile(filepaths=search_rules)
            vars_dict['binary_rules'] = yara.compile(filepaths=binary_rules)
        return vars_dict
def manual_setup():
    # Saving options (workpath and saveall):
    while True:
        workpath = Prompt.ask(
            lib.stylize("Enter the path you wish to save text documents to (Leave empty for current directory)",
                        'input'),
            default=sys.path[0],
            show_default=False)
        if not path.isdir(workpath):
            console.print(lib.stylize("Invalid path, check input...", 'error'))
            continue
        print(lib.stylize("Valid Path...", 'success'))
        workpath = workpath if any([workpath.endswith('\\'), workpath.endswith('/')]) else f'{workpath}/'
        break
    saveall = Confirm.ask(lib.stylize("Save all documents (Enter N to only save matched documents)?", 'input'))
    # Services to Enable (services):
    # TODO: redesign this whole bit
    while True:
        for x in collectors.service_names.keys():
            print(lib.stylize(f"[{x}]: {collectors.service_names[x]}", 'status'))
        service_choice = Prompt.ask(lib.stylize(
            "Enter the number(s) of the services you wish to scrape, separated by a comma (Leave blank for All)",
            'input'),
                                    default="All",
                                    show_default=False)
        if service_choice == "All":
            services = [collectors.service_names[x] for x in collectors.service_names.keys()]
        else:
            services = [collectors.service_names[int(x)] for x in service_choice if
                        int(x) in collectors.service_names.keys()]
        services = list(collectors.service_names.values()) if services == [] else services
        break
    # Looping
    stop_input = Confirm.ask(lib.stylize("Run in a constant loop?", 'input'))
    if not stop_input:
        stop_input = IntPrompt.ask(lib.stylize("Enter the amount of times you want to fetch the archives", 'input'))
        stop_input = True if stop_input <= 0 else stop_input
    # Limiter and Cooldown
    limiter = IntPrompt.ask(lib.stylize("Enter the request limit you wish to use (recommended: 5)", 'input'),
                            default=5,
                            show_default=False)
    cooldown = IntPrompt.ask(
        lib.stylize("Enter the cooldown between IP bans/Archive scrapes (recommended: 600)", 'input'),
        default=600,
        show_default=False)
    # YARA (yara_scanning)
    yara_scanning = Confirm.ask(lib.stylize("Enabled scanning with YARA rules", 'input'))
    # Building Settings Dict:
    vars_dict = {
        'workpath': workpath,
        'stop_input': stop_input,
        'limiter': limiter,
        'cooldown': cooldown,
        'yara_scanning': yara_scanning,
        'services': services,
        'saveall': saveall,
        'rule_count': (0, 0)
    }
    if yara_scanning:
        search_rules = {f.split('.')[0]: path.join(f'{sys.path[0]}/yara_rules/general_rules/', f) for f in
                        listdir(f'{sys.path[0]}/yara_rules/general_rules/') if
                        path.isfile(path.join(f'{sys.path[0]}/yara_rules/general_rules/', f)) and f.endswith(
                            ".yar") or f.endswith(".yara")}
        binary_rules = {f.split('.')[0]: path.join(f'{sys.path[0]}/yara_rules/binary_rules/', f) for f in
                        listdir(f'{sys.path[0]}/yara_rules/binary_rules/') if
                        path.isfile(path.join(f'{sys.path[0]}/yara_rules/binary_rules/', f)) and f.endswith(
                            ".yar") or f.endswith(".yara")}
        vars_dict['rule_count'] = (len(search_rules), len(binary_rules))
    # Saving
    savechoice = Confirm.ask(lib.stylize('Save configuration to file for repeated use?', 'input'))
    if savechoice:
        json.dump(vars_dict, open(f"config.json", 'w'))
    return vars_dict

def main(args):
    if len(args) > 1:
        vars_dict = load_config(args[1])
    else:
        vars_dict = manual_setup()
    layout = UI(console, vars_dict)
    layout.console.clear()
    with Live(layout.layout, refresh_per_second=60, screen=True, console=layout.console) as live:
        runs = 0
        while True:
            with ThreadPoolExecutor(max_workers=len(vars_dict['services'])) as executor:
                for service in vars_dict['services']:
                    executor.submit(collectors.services[service], layout, vars_dict)
            if not vars_dict['stop_input']:
                if runs >= vars_dict['stop_input']:
                    layout.update_output(lib.stylize(f"Runs Complete, Operation Finished...", 'success'))
                    exit()
            layout.update_output(lib.stylize(f"All services scraped, cooling down for {vars_dict['cooldown']} seconds", 'status'))
            sleep(vars_dict['cooldown'] / 2)
            layout.update_output(lib.stylize("Halfway through cooldown.", 'status'))
            sleep(vars_dict['cooldown'] / 2)
            layout.update_output(lib.stylize("Continuing...", 'status'))

if __name__ == '__main__':
    main(sys.argv)
