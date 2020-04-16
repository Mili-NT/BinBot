import lib
from time import sleep
from bs4 import BeautifulSoup
# Scraping functions:
def pastebin(vars_dict):
    """
    This function fetches the pastebin archive and all the pastes in it. It passes them to archive_engine(),
    then sleeps per the time specified by vars_dict['cooldown']

    :param vars_dict: dict of necessary variables returned from config()
    :return: Nothing
    """
    # Fetch the pastebin public archive
    lib.print_status(f"Starting pastebin run...")
    arch_page = lib.connect("https://pastebin.com/archive")
    arch_soup = BeautifulSoup(arch_page.text, 'html.parser')
    sleep(2)
    # Parse the archive HTML to get the individual document URLs
    table = arch_soup.find("table", attrs={'class': "maintable"})
    parameters = [a['href'] for a in table.findAll('a', href=True) if 'archive' not in a['href']]
    # For each paste listed, connect and pass the text to archive_engine()
    for param in parameters:
        param = param[1:] # removes the leading forward slash
        document_page = lib.connect(f"https://pastebin.com/{param}")
        document_soup = BeautifulSoup(document_page.text, 'html.parser')
        # Fetch the raw text and pass to archive_engine()
        unprocessed = document_soup.find('textarea').contents[0]
        identifier = f'pastebin-{param}'
        lib.archive_engine(unprocessed, identifier, vars_dict)
        sleep(vars_dict['limiter'])
    lib.print_success("All pastebin pastes processed.")
    sleep(vars_dict['cooldown'])
def ixio(vars_dict):
    """
    This is the scraping function for ix.io. It works very similar to the pastebin() function,
    and fetches a list of documents from an archive, processes them, and cools down

    :param vars_dict: dict of necessary variables returned from config()
    :return: nothing
    """
    lib.print_status("Starting ix.io run...")
    # Connect to archive and gather individual document parameters
    soup = BeautifulSoup(lib.connect("http://ix.io/user/").text, 'html.parser')
    # The parameter is sanitized (has its leading and trailing forward slashes removed) during this comprehension
    parameters = set([a['href'].replace('/', '') for a in soup.findAll('a', href=True)])
    # Loop through parameters and get raw text
    for param in parameters:
        document_soup = BeautifulSoup(lib.connect(f'http://ix.io/{param}').text, 'html.parser')
        # Pass raw text to archive engine
        identifier = f'ixio-{param}'
        lib.archive_engine(str(document_soup), identifier, vars_dict)
        sleep(vars_dict['limiter'])
    lib.print_success("All ix.io pastes processed.")
    sleep(vars_dict['cooldown'])
def slexy(vars_dict):
    """
    Scraping function for slexy. This one is almost identical to ix.io, with the exception of having some
    tables to dig through. It also has a heavier rate limit, so a minimum limiter is enforced

    :param vars_dict: dict of necessary variables returned from config()
    :return: nothing
    """
    lib.print_status("Starting slexy run...")
    # Connect to archive and get parameters for individual documents
    soup = BeautifulSoup(lib.connect("https://slexy.org/recent").text, 'html.parser')
    table = soup.find("table", attrs={'id': "recent_pastes"})
    parameters = set([a['href'] for a in table.findAll('a', href=True)])
    # Loop through parameters
    for param in parameters:
        # Connect and fetch the raw text
        document_soup = BeautifulSoup(lib.connect(f'https://slexy.org{param}').text, 'html.parser')
        document_table = document_soup.findAll("table")
        raw_parameter = [a['href'] for a in document_table[1].findAll('a', href=True) if 'raw' in a['href']]
        unprocessed = BeautifulSoup(lib.connect(f'https://slexy.org{raw_parameter}').text, 'html.parser').find('pre').contents[0]
        # Pass to archive engine
        # We remove the /view/ from the param for file naming purposes
        identifier = f'slexy-{param.split("/view/")[1]}'
        lib.archive_engine(unprocessed, identifier, vars_dict)
        sleep(5) if vars_dict['limiter'] < 5 else sleep(vars_dict['limiter'])
    lib.print_success("All slexy pastes processed.")
    sleep(vars_dict['cooldown'])
# Dict for selecting services to enable
service_names = {1: 'pastebin', 2: 'ixio', 3:'slexy'}
# Dict for calling the scraping functions by enumerating vars_dict['services']
services = {'pastebin':pastebin, 'ixio':ixio, 'slexy':slexy}
