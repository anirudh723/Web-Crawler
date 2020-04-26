High Level Approach:

I designed a class called WebCrawler which had function to login, crawl, make GET/POST requests, etc.
My class had properties to represent the token, session_id, and had data structures to organize the uncrawled
pages (frontier), visited pages, cookies, etc
I created helper functions to deal with requests, extracting headers from responses, parsing url prior to making
the request, reading chunked data responses (HTTP 1.1), etc.
The crawler first sends a GET request to '/accounts/login/?next=/fakebook/' under host 'fring.ccs.neu.edu' on port 80.
After receiving the token and session_id, the crawler made a POST request with my credentials to log into Fakebook.
The crawler then added the list of friends into the queue, which was used to represented the uncrawled links.
I used a list structure to add every link I visited into, to ensure the crawler doesn't fall into an infinite loop.
Errors such as 302 (Found) were handled by redirecting the request to the new url.
Secret flags were randomly hidden throughout the site, the objective was to find five flags while crawling.
Once the five flags are found, the program terminates.

Challenges Faced:

Initially, the challenge was properly creating the requests to be sent to the server. I was not adding new lines at the
end of my headers when creating the request, and for that reason I was receiving client-side errors (ex: 408 Request
Timeout). Another challenge was understanding how to track the frontier. Making sure that I was adding every friend
on all pages of an individual's profile and that I was ensuring that I marked them in my 'visited' list was very
crucial.

Testing:

I used Postman to make sample GET/POST requests. This allowed me to see whether I was getting back correct responses.
Print statements were used to debug any client side logic. I also inspected network activity via my browser to see
what my crawler should simulate when making requests.

Enhancements/Future Improvements:
I used multi-threading to speed up the performance of the web crawler. The crawler can now crawl up to 75 friends at
once. 
To improve my crawler program, I would implement Accept-Encoding: gzip. Having compressed HTTP responses would 
definitely speed up my crawler. 