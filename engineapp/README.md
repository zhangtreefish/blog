# A Simple Blog App Built with Google App Engine
### Explore my app at [here](http://gaejinjablog.appspot.com/blog)
## Features:
--Front page that lists blog posts: /welcome<br />
--A form to submit new entries: /newpost<br />
--Blog posts have their own page: /post/<post_id>.<br />

--A signup form that validates inputs and displays error(s):
  /signup; upon success the user is directed to the welcome page;<br />
-- If a user visits without being signed in (i.e. having a cookie),
   then redirected to the signup page<br />
-- Passwords stored securely as salted hash<br />

-- A login form that validates inputs and displays error(s):
   /login; on success directed to the same welcome page<br />

-- A logout form that validates inputs and displays error(s):
   /logout; on success the cookie is cleared and user is redirected
    to the signup page.<br />

## How to run this app from your machine

* Run git clone https://github.com/zhangtreefish/blog.git
* Run inside the directory engineapp:`dev_appserver.py . `
  and go to localhost:8080/blog
* Create a project at Google Cloud Platform, asign yourself a role
  in the project at IAM/Admin tab. To deploy run
 `gcloud app deploy`

## References
[1. webapp2 Building URIs](https://webapp2.readthedocs.io/en/latest/guide/routing.html#guide-routing-building-uris)<br />
[2. Deploying a Python App](https://cloud.google.com/appengine/docs/python/tools/uploadinganapp)<br />
[3. quickstart](https://cloud.google.com/appengine/docs/python/quickstart)
