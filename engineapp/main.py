#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
from validator import valid_month, valid_day, valid_year, escape_html

form="""
<p> What's your birthday?</p>
<form method="post">
    <label>Month
        <input type="text" name="month" value="{month}">
    </label>
    <label>Day
        <input type="text" name="day" value="{day}">
    </label>
    <label>Year
        <input type="text" name="year" value="{year}">
    </label>
    <div style="color:red">{error}</div>
    <br>
    <input type="submit">
</form>
"""

class MainHandler(webapp2.RequestHandler):

    def write_form(self, error='', month='', day='', year=''):
        self.response.out.write(form.format(error=error, month=escape_html(month), day=escape_html(day), year=escape_html(year)))

    def get(self):
        self.write_form()

    def post(self):
        user_month = self.request.get("month")
        user_day = self.request.get("day")
        user_year = self.request.get("year")
        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
            self.write_form("You entered invalid value(s) ", user_month , user_day, user_year)
        else:
            self.redirect('/thank?month={0}&day={1}&year={2}'.format(user_month, user_day, user_year))

class ThankHandler(webapp2.RequestHandler):
    def get(self):
        month = self.request.get("month")
        day = self.request.get("day")
        year = self.request.get("year")
        self.response.out.write("You entered the validated value(s) "+ month +' '+ day+', '+ year)

class FormHandler(webapp2.RequestHandler):
    def post(self):
        q = self.request.get("q")
        # self.response.write(q)
        # useful for debug:
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write(self.request)

# Remove debug=True before final deployment
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/thank', ThankHandler),
    ('/formTest', FormHandler)
], debug=True)
