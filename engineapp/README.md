# A Simple Blog App Built with Google App Engine
### Explore my app at [here](http://gaejinjablog.appspot.com/blog)
termed {baseUrl} from here on.
## Features:
--Front page that lists blog posts: {baseUrl}/welcome<br />
--A form to submit new entries: {baseUrl}/newpost<br />
--Blog posts have their own page: {baseUrl}/post/<post_id>.<br />

--A signup form that validates inputs and displays error(s):
  {baseUrl}/signup; upon success the user is directed to the
  welcome page;<br />
-- If a user visits without being signed in (i.e. having a cookie),
   then redirected to the signup page<br />
-- Passwords stored securely as salted hash<br />

-- A login form that validates inputs and displays error(s):
   {baseUrl}/login; on success directed to the same welcome page<br />

-- A logout form that validates inputs and displays error(s):
   {baseUrl}/logout; on success the cookie is cleared and user is
   redirected to the signup page.<br />

## How to run this app from your machine

* Run git clone https://github.com/zhangtreefish/blog.git
* Run inside the directory engineapp:`dev_appserver.py . `
  and go to localhost:8080/blog
* To deploy: create a project at Google Cloud Platform, asign
  yourself a role in the project at IAM/Admin tab. To deploy run
 `gcloud app deploy`

## References
1__ webapp2 Building URIs: https://webapp2.readthedocs.io/en/latest/guide/routing.html#guide-routing-building-uris
2__ Deploying a Python App: https://cloud.google.com/appengine/docs/python/tools/uploadinganapp
3__ quickstart: https://cloud.google.com/appengine/docs/python/quickstart
