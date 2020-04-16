import lib
from time import sleep
from bs4 import BeautifulSoup

def pastebin(vars_dict):
    """
    This function fetches the pastebin archive and all the pastes in it. It passes them to archive_engine(),
    then sleeps per the time specified by vars_dict['cooldown']

    :param vars_dict: dict of necessary variables returned from config()
    :return: Nothing
    """
    # Fetch the pastebin public archive
    lib.print_status(f"Getting archived pastes...")
    arch_page = lib.connect("https://pastebin.com/archive")
    arch_soup = BeautifulSoup(arch_page.text, 'html.parser')
    sleep(2)
    # Parse the archive HTML to get the individual document URLs
    table = arch_soup.find("table", attrs={'class': "maintable"})
    parameters = [a['href'] for a in table.findAll('a', href=True) if 'archive' not in a['href']]
    # For each paste listed, connect and pass the text to archive_engine()
    for h in parameters:
        param = h[1][1:]
        document_page = lib.connect(f"https://pastebin.com/{param}")
        document_soup = BeautifulSoup(document_page.text, 'html.parser')
        # Fetch the raw text and pass to archive_engine()
        unprocessed = document_soup.find('textarea').contents[0]
        lib.archive_engine(unprocessed, param, vars_dict)
        sleep(vars_dict['limiter'])
    lib.print_success("All pastes for current run processed.")
    sleep(vars_dict['cooldown'])
def ixio(vars_dict):
    """
    This is the scraping function for ix.io. It works very similar to the pastebin() function,
    and fetches a list of documents from an archive, processes them, and cools down

    :param vars_dict: dict of necessary variables returned from config()
    :return: nothing
    """
    soup = BeautifulSoup(lib.connect("http://ix.io/user/").text, 'html.parser')
    parameters = set([a['href'].replace('/', '') for a in soup.findAll('a', href=True)])
    for param in parameters:
        document_soup = BeautifulSoup(lib.connect(f'http://ix.io/{param}'), 'html.parser')
        unprocessed = document_soup.find('pre').contents[0]
        lib.archive_engine(unprocessed, param, vars_dict)
        sleep(vars_dict['limiter'])
    sleep(vars_dict['cooldown'])

service_names = {1: 'pastebin', 2: 'ix.io'}
services = {1: pastebin, 2:ixio}