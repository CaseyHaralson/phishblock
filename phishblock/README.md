# PhishBlock

PhishBlock is a Chrome web browser extension. 
It helps to block phishing through email:
* checks the sender's email address and compares it to all the links in the email to see if they come from the same place (domain checking)
* adds a red box around any suspicious link data and around attachments
* adds a reminder to check the sender's email and any attachments (make sure they are expected)
* removes all links from the email (We should't be clicking on links in email! It's best to go to the bank's website and get the message or other information there, for example.)

Currently the extension only works with Gmail.

**Link:** [Chrome Web Store](https://chrome.google.com/webstore/detail/phishblock/mfigocgdflddipodffjfpbjmplhhfbeh)


## Getting Started

There are a couple of ways to download PhishBlock:
* [Download the zip](https://github.com/CaseyHaralson/chromeplugins/archive/master.zip)
* Clone the repo: `git clone https://github.com/caseyharalson/chromeplugins.git`


## Usage

**Note:** these steps below are only for development!  Use the Chrome Web Store link above to install PhishBlock regularly.

Open the Chrome "Settings" page and click on the "Extensions" tab on the left panel.

Click on the "Developer mode" checkbox to make it checked.

Click on the "Load unpacked extension..." button and navigate to the folder where you downloaded PhishBlock.
Make sure the folder you select is the actual PhishBlock folder under the chromeplugins repo.

Close and reopen any tabs that have Gmail open.