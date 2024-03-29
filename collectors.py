import lib
from time import sleep
from bs4 import BeautifulSoup

# Template Function:
def template_function(layout, vars_dict):
    """
    :param vars_dict: All scraping functions are passed vars_dict, which contains all variables needed for operation
    :return: Nothing, passes the documents to lib.archive_engine()
    """
    layout.update_output(lib.stylize("Starting <enter service name> run", 'status'))
    # Connect to the archive page of the service and create a soup object
    template_page = lib.connect(layout, "https://templatebin.com/archive")
    template_soup = BeautifulSoup(template_page.text, 'html.parser')
    # parse the archive page to get links to individual documents.
    # The actual code here will vary depending on the HTML of your target service
    table = template_soup.find("table", attrs={'class':'table_of_documents'})
    parameters = [a['href'] for a in table.findAll('a', href=True)]
    # Loop through each parameter and get the document:
    for param in parameters:
        # connect to document and make a soup object:
        document_page = lib.connect(layout, f"https://templatebin.com/{param}")
        document_soup = BeautifulSoup(document_page.text, 'html.parser')
        # Do whatever html work (if any) you need to get the raw text.
        # If it's just in a <pre> tag, you can simple do str(document_soup)
        unprocessed = document_soup.find('textarea').contents[0]
        # the indentifer is used to name the file:
        identifier = f"service_name-{param}"
        # Pass the text to lib.archive_engine() for matching and saving:
        lib.archive_engine(layout, unprocessed, identifier, vars_dict)
        # and wait for the amount of time specified by limiter:
        sleep(vars_dict['limiter'])
# Scraping functions:
def pastebin(layout,vars_dict):
    """
    This function fetches the pastebin archive and all the pastes in it. It passes them to archive_engine(),
    then sleeps per the time specified by vars_dict['cooldown']

    :param vars_dict: dict of necessary variables returned from config()
    :return: Nothing
    """
    # Fetch the pastebin public archive
    layout.update_output(lib.stylize(f"Starting pastebin run...", 'status'))
    arch_page = lib.connect(layout, "https://pastebin.com/archive")
    arch_soup = BeautifulSoup(arch_page.text, 'html.parser')
    sleep(2)
    # Parse the archive HTML to get the individual document URLs
    table = arch_soup.find("table", attrs={'class': "maintable"})
    parameters = [a['href'] for a in table.findAll('a', href=True) if 'archive' not in a['href']]
    # For each paste listed, connect and pass the text to archive_engine()
    count = 0
    for param in parameters:
        param = param[1:] # removes the leading forward slash
        document_page = lib.connect(layout, f"https://pastebin.com/{param}")
        document_soup = BeautifulSoup(document_page.text, 'html.parser')
        # Fetch the raw text and pass to archive_engine()
        unprocessed = document_soup.find('textarea').contents[0]
        identifier = f'pastebin-{param}'
        lib.archive_engine(layout, unprocessed, identifier, vars_dict)
        sleep(vars_dict['limiter'])
    layout.update_output(lib.stylize("All pastebin pastes processed.", 'success'))
def ixio(layout, vars_dict):
    """
    This is the scraping function for ix.io. It works very similar to the pastebin() function,
    and fetches a list of documents from an archive, processes them, and cools down

    :param vars_dict: dict of necessary variables returned from config()
    :return: nothing
    """
    layout.update_output(lib.stylize("Starting ix.io run...", 'status'))
    # Connect to archive and gather individual document parameters
    soup = BeautifulSoup(lib.connect(layout, "http://ix.io/user/").text, 'html.parser')
    # The parameter is sanitized (has its leading and trailing forward slashes removed) during this comprehension
    parameters = set([a['href'].replace('/', '') for a in soup.findAll('a', href=True)])
    # Loop through parameters and get raw text
    count = 0
    for param in parameters:
        document_soup = BeautifulSoup(lib.connect(layout, f'http://ix.io/{param}').text, 'html.parser')
        # Pass raw text to archive engine
        identifier = f'ixio-{param}'
        lib.archive_engine(layout, str(document_soup), identifier, vars_dict)
        sleep(vars_dict['limiter'])
    layout.update_output(lib.stylize("All ix.io pastes processed.", 'success'))
def slexy(layout, vars_dict):
    """
    Scraping function for slexy. This one is almost identical to ix.io, with the exception of having some
    tables to dig through. It also has a heavier rate limit, so a minimum limiter is enforced

    :param vars_dict: dict of necessary variables returned from config()
    :return: nothing
    """
    layout.update_output(lib.stylize("Starting slexy run...", 'status'))
    # Connect to archive and get parameters for individual documents
    soup = BeautifulSoup(lib.connect(layout, "https://slexy.org/recent", verify_ssl=False).text, 'html.parser')
    table = soup.find("table", attrs={'id': "recent_pastes"})
    parameters = set([a['href'] for a in table.findAll('a', href=True)])
    # Loop through parameters
    layout.update_output(lib.stylize(f"{len(parameters)} slexy params", 'status'))
    for param in parameters:
        # Connect and fetch the raw text
        document_soup = BeautifulSoup(lib.connect(layout, f'https://slexy.org{param}', verify_ssl=False).text, 'html.parser')
        document_table = document_soup.findAll("table")
        raw_parameter = [a['href'] for a in document_table[1].findAll('a', href=True) if 'raw' in a['href']][0]
        unprocessed = BeautifulSoup(lib.connect(layout, f'https://slexy.org{raw_parameter}', verify_ssl=False).text, 'html.parser')
        # Pass to archive engine
        # We remove the /view/ from the param for file naming purposes
        identifier = f'slexy-{param.split("/view/")[1]}'
        lib.archive_engine(layout, str(unprocessed), identifier, vars_dict)
        sleep(5) if vars_dict['limiter'] < 5 else sleep(vars_dict['limiter'])
    layout.update_output(lib.stylize("All slexy pastes processed.", 'success'))
# Dict for selecting services to enable
service_names = {1: 'pastebin', 2: 'ixio', 3:'slexy'}
# Dict for calling the scraping functions by enumerating vars_dict['services']
services = {'pastebin':pastebin, 'ixio':ixio, 'slexy':slexy}
