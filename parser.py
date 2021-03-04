
from bs4 import BeautifulSoup
class HtmlParser(object):
    def __init__(self, html):
        self.soup = BeautifulSoup(html, 'html5lib')
    @property
    def hrefs(self):
        a_tags = self.soup.find_all("a", {"href": True})
        for tag in a_tags:
            yield tag['href']
    @property
    def script_text(self):
        scripts = self.soup.find_all('script')
        return [script.text for script in scripts]
