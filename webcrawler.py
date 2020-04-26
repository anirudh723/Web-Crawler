#!/usr/bin/env python

import socket
import threading
from urllib.parse import urlparse
import sys
from queue import Queue, Empty
import re

DOMAIN = 'http://fring.ccs.neu.edu/'
FAKEBOOK = DOMAIN + 'fakebook/'
LOGIN_URL = DOMAIN + 'accounts/login/?next=/fakebook/'
PORT = 80

# Regex patterns
STATUS_PATTERN = "(HTTP\/1\.1) +?(\d+)(.+)"
COOKIE_PATTERN = "(\w+)=(\w+);(.+)"
FBID_PATTERN = '(href="/fakebook/(\d+?)/")+'
FLAG_PATTERN = "secret_flag.+FLAG: ([a-zA-Z0-9]{64})"


"""
    Represents a Web crawler, which has functions to login, crawl, GET, POST, etc
"""
class WebCrawler:

    """
        Initialize the WebCrawler
    """
    def __init__(self):
        self.token = ''
        self.session_cookie = ''
        self.cookies = {}
        self.flags = []
        self.visited = {}
        self.frontier_queue = Queue()

    '''
        Given the host name and request message, set up a socket, connect to the host and port,
        send the request, and receive the response (could be partial) back on the socket. 
        Return the response and socket object.
    '''
    def deal_request(self, host, request):
        # Set up the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, PORT))
        # send request and return response and sock object
        sock.send(request.encode('utf-8'))
        data = sock.recv(4096).rstrip().decode()
        return data, sock

    '''
        Extracts the header from the given data
        Also, adds the cookies to this WebCrawler and checks whether the csrf token
        and session were in data
    '''
    def extract_headers(self, data):
        headers = {}
        headers['Set-Cookie'] = []
        num_of_newlines = 0
        # for every line of data...
        for line in data.split("\n"):
            line_stripped = line.strip()
            # counts the number of newlines
            if line_stripped == "\n":
                num_of_newlines += 1
                continue
            # usually two newlines means headers are done -> break
            # or when the html documents begins (<) -> break
            if num_of_newlines == 2 or len(line_stripped) > 0 and line_stripped[0] == '<':
                break

            # find status message and status code
            if 'HTML/1.1' in line:
                # regex pattern to match response code and message
                status_content = re.match(STATUS_PATTERN, line)
                status_message = status_content.group(2) + status_content.group(3)
                status_code = int(status_content.group(2))
                headers['status'] = status_message
                headers['status_code'] = status_code

            # found a header, extract key and value and add to headers
            elif ':' in line:
                colon_index = line.index(':')
                k = line[:colon_index]
                v = line[colon_index + 1:]
                # new header
                if k not in headers:
                    headers[k] = v.strip()
                # header is part of a list, such as Set-Cookie
                elif isinstance(headers[k], list):
                    headers[k].append(v.strip())
                # else add a list of the key and value at the key index
                else:
                    headers[k] = [headers[k], v.strip()]

        # update WebCrawler's cookies dictionary to track whether client is logged into site
        # when logging into fakebook, store the csrftoken and sessionid
        for cookie_header in headers["Set-Cookie"]:
            cookie = re.match(COOKIE_PATTERN, cookie_header)
            cookie_k = cookie.group(1)
            cookie_v = cookie.group(2)
            self.cookies[cookie_k] = cookie_v

            if cookie_k == 'csrftoken':
                self.token = cookie_v
            elif cookie_k == 'sessionid':
                self.session_cookie = cookie_v
        return headers

    """
        Extracts the host and path from the given url.
        Used for making requests.
    """
    def parse_url(self, url, request_method):
        # Build a urlparse object to extract info from given url
        p_url = urlparse(url)
        # Extract host
        host = p_url.netloc
        # if there is a path in the url, then assign path to that, otherwise path is just '/'
        if p_url.path:
            path = p_url.path
        else:
            path = '/'

        # For GET request, query params may be added to path if given url has any
        if request_method == "GET":
            # add the query params with ? before each
            if p_url.query:
                path += '?' + p_url.query
        return host, path

    """
        HTTP 1.1 supports chunked encoding. This is to handle that.
        Chunks are read and added to the data
    """
    def read_all_data(self, data, sock):
        while True:
            initial_length = len(data)
            try:
                # try to read more chunks
                chunk = sock.recv(4096).rstrip().decode()
                data += chunk
            except:
                break
            # no more data was read
            if initial_length == len(data):
                break
        return data

    """
        Make a GET request to the given url.
        Returns headers and data from response 
    """
    def GET(self, url):
        host, path = self.parse_url(url, "GET")

        # create request
        request = 'GET ' + path + ' HTTP/1.1\nHost: ' + host

        # False when initially logging in, only need the above line
        # Once the token and session are established, the headers
        # below are added to each GET request.
        if self.token and self.session_cookie:
            request += '\nUser-Agent: AnirudhSingh/1.1\n'
            request += f'Cookie: {self.print_cookies()}\n'
            request += 'Accept-Language: en-us\n'
        # double newline to end header information
        request += '\n\r\n'
        # send request and get back response
        data, sock = self.deal_request(host, request)

        # to read all the data
        data = self.read_all_data(data, sock)

        sock.close()
        # extract headers from response
        headers = self.extract_headers(data)
        return headers, data

    """
        Make a POST request to the given url with the given keyword args
        Returns headers and data from response 
    """
    def POST(self, url, **kwargs):
        host, path = self.parse_url(url, "POST")

        # add parameters, separated by an &
        content = ''
        for param, val in kwargs.items():
            content += f'{param}={val}&'
        # remove the last &
        content = content[: -1]

        # create request
        request = 'POST ' + path + ' HTTP/1.1\nHost: ' + host + "\n"
        request += 'User-Agent: Mozilla/5.0\n'
        request += f'Content-Length: {str(len(content))}\n'
        request += 'Accept-Language: en-us\n'
        request += f"Referer: {LOGIN_URL}\n"
        request += f'Cookie: {self.print_cookies()}\n\n'
        request += content + '\r\n'

        # send request
        data, sock = self.deal_request(host, request)

        # to read all the data
        data = self.read_all_data(data, sock)

        sock.close()
        # extract headers from response
        headers = self.extract_headers(data)
        return headers, data

    """
        Prints the cookies to be added to request.
        For example, key1=value1;key2=value2;key3=value3
    """
    def print_cookies(self):
        cookies = ''
        for key, value in self.cookies.items():
            cookies += f'{key}={value};'
        return cookies

    """
        Logs into Fakebook
    """
    def login(self, username, password):
        # First, make a GET request to get the login page info. Need the csrf token to log in
        self.GET(LOGIN_URL)
        # Make a POST request to the login page, with my user/pass, and with the obtained token
        p_headers, p_data = self.POST(LOGIN_URL, username=username, password=password,
                                      next='%2Ffakebook%2F', csrfmiddlewaretoken=self.token)
        # When POSTing, if the URL got redirected (302), then make a GET to the url specified in the Location header
        if "Location" in p_headers:
            self.first_page = self.GET(p_headers["Location"])
        else:
            self.first_page = "No first page"

    """
        For all pages of current person's friends, check each friend and see if they have not been visited yet
        If it is a new individual, add them to the frontier_queue to be visited
    """
    def queue_friends(self, html):
        for link in re.finditer(FBID_PATTERN, html):
            for id in [link.group(2)]:
                if id not in self.visited:
                    self.frontier_queue.put(id, block=True)
                    self.visited[id] = 1

    """
        For the given html content, look for a tag with the secret_flag class and extract the 
        64 byte key after the FLAG: word and adds the flag to the list of flags
    """
    def find_flag(self, html):
        # regex pattern that matches the 64 characters after secret_flag...FLAG:
        search = re.findall(FLAG_PATTERN, html)
        if search:
            self.flags.append(search[0])

    """
        Given the url of some individual's profile, makes a GET request to the link 
        that opens their list of friends.
    """
    def get_friends(self, url):
        headers, friends_of_friend_data = self.GET(url + 'friends/1/')
        # adds this person's friends to the queue to be crawled later
        self.queue_friends(friends_of_friend_data)
        # regex pattern to find the number of pages
        page_regex = re.findall('Page 1 of \d', friends_of_friend_data)
        num_pages = int(page_regex[0][10:]) if page_regex else 1

        # iterates through all the pages of this person's friends (1st page already done),
        # queue their friend's to be crawled later
        for i in range(2, num_pages):
            headers, next_friend = self.GET(url + f'friends/{i}/')
            self.queue_friends(next_friend)

    """
        Makes a GET request to the person who was next to be crawled's profile.
    """
    def search_help(self, id):
        # appends the friend's id to the fakebook url to reach the friend profile
        profile_url = FAKEBOOK + id + '/'
        # get info on friend
        headers, data = self.GET(profile_url)
        # call find_flag to search for a flag there (if there is one), and call load_friends
        # that will GET this friend's list of friends
        self.find_flag(data)
        self.get_friends(profile_url)

    """
        Search the next person in the queue
    """
    def search_next(self):
        try:
            next_profile_id = self.frontier_queue.get(timeout=0.05)
            self.search_help(next_profile_id)
        except Empty:
            pass

    """
        Crawl Fakebook
    """
    def crawl(self):
        # start at friends on main_page
        self.queue_friends(self.first_page[1])

        # while I do not have my 5 secret flags, keep crawling
        while len(self.flags) < 1:
            # uses multi-threading to speed up crawler. Can search up to 75 friends at once
            if threading.activeCount() < 75:
                threading.Thread(target=self.search_next).start()
            else:
                self.search_next()

        # once I have my 5 flags, terminate crawler and print my flags
        for flag in self.flags:
            print(flag)


"""
    driver function
"""
def main():
    username = sys.argv[1]
    password = sys.argv[2]
    crawler = WebCrawler()
    crawler.login(username, password)
    crawler.crawl()


if __name__ == '__main__':
    main()
