
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {


    var emailHeaderSelector = '.kv',
        emailBlockSelector = 'div.gs',
        senderElementSelector = 'h3 span.gD',
        recipientElementMeSelector = 'span.hb span.g2:contains("me")',
        recipientElementSelector = 'span.hb span.g2',
        linkSelector = 'a',
        calendarBlockLinkSelector = '.aHl a',
        headerBlockLinkSelector = '.iv a', // header could be gE/iv/gt
        spanBlockLinkSelector = '.acS a',
        attachmentParentClass = 'aZo',
        emailBodyElementSelector = 'div.a3s',
        attachmentsAreaSelector = 'div>:contains("Attachments area"), div>:contains(" Attachments")'

    var suspiciousLinkClass = 'fishhook-suspicious-link',
        linkClass = 'fishhook-link',
        suspiciousAttachmentClass = 'fishhook-suspicious-attachment',
        suspiciousEmailBodyClass = 'fishhook-suspicious-email-body',
        emailBodyClass = 'fishhook-email-body'


    function log(message) {
        console.log(message);
    }


    function textLooksLikeALink(url, text) {
        //log('testing text: ' + text);

        if (text == null || text.length == 0) return false;

        var urlRegex = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
        return urlRegex.test(text)
            || text.indexOf('www.') > -1 || text.indexOf('.com') > -1
            || text.indexOf('.net') > -1 || text.indexOf('.org') > -1
            || text.indexOf('.co') > -1 ||
            (url.indexOf(text) > -1 && text.indexOf('.') > -1);

        //return text.indexOf('http://') > -1 || text.indexOf('https://') > -1
        //    || text.indexOf('www.') > -1 || text.indexOf('.com') > -1
        //    || text.indexOf('.net') > -1 || text.indexOf('.org') > -1
        //    || text.indexOf('.co') > -1;
    }


    function processOpenEmailSections() {
        log('processing email blocks');
        var emailBlocks = $(emailBlockSelector);
        if (emailBlocks != null && emailBlocks.length > 0) {
            for (var iBlocks = 0; iBlocks < emailBlocks.length; iBlocks++) {
                var emailBlock = emailBlocks[iBlocks];

                var senderEmailBlock = null,
                    senderEmail = null,
                    senderDomain = null,
                    senderSubdomain = null,
                    recipientEmail = null,
                    suspiciousLinkFound = false,
                    suspiciousAttachmentFound = false;


                // lets find the current block's sender
                // and it's parent (for later)
                log('finding sender email');
                var senderElement = $(emailBlock).find(senderElementSelector);
                if (senderElement != null && senderElement.length > 0 && senderElement[0].attributes.hasOwnProperty('email')) {
                    var senderEmail = senderElement[0].attributes['email'].value;
                    senderEmailBlock = senderElement[0].parentElement;

                    log('sender email: ' + senderEmail);
                }


                // lets find the sender's domain
                log('finding sender domain');
                if (senderEmail != null && senderEmail.indexOf('@') > -1) {
                    senderDomain = senderSubdomain = senderEmail.substring(senderEmail.indexOf('@') + 1);

                    var domainPieces = senderDomain.split('.');
                    if (domainPieces.length > 2) {
                        senderDomain = domainPieces[domainPieces.length - 2] + '.' + domainPieces[domainPieces.length - 1];
                    }

                    log('sender domain: ' + senderDomain);
                }


                // lets find the recipient
                log('finding recipient email');
                var recipientElementMe = $(emailBlock).find(recipientElementMeSelector);
                var recipientElement = $(emailBlock).find(recipientElementSelector); // in case I'm sending the email
                if (recipientElementMe != null && recipientElementMe.length == 1) recipientElement = recipientElementMe;
                if (recipientElement != null && recipientElement.length > 0 && recipientElement[0].attributes.hasOwnProperty('email')) {
                    var recipientEmail = recipientElement[0].attributes['email'].value;

                    log('recipient email: ' + recipientEmail);
                }


                // lets look at all the links in the email block (skip links inside calendar block and header)
                // and make sure it comes from the correct domain
                // or that it's a mailto link to the sender or recipient
                var linksInBlock = $(emailBlock).find(linkSelector)
                    .not($(emailBlock).find(calendarBlockLinkSelector))
                    .not($(emailBlock).find(headerBlockLinkSelector))
                    .not($(emailBlock).find(spanBlockLinkSelector));
                if (linksInBlock != null && linksInBlock.length > 0) {
                    for (var iLink = 0; iLink < linksInBlock.length; iLink++) {
                        var link = linksInBlock[iLink],
                            linkHref = link.href,
                            linkDomain = null,
                            linkParent = link.parentElement;

                        //console.log('processing link: ' + linkHref);

                        // find the link domain
                        if (linkHref != null && (linkHref.indexOf('http://') > -1 || linkHref.indexOf('https://') > -1)) {
                            linkDomain = linkHref.replace('http://', '').replace('https://', '');
                            if (linkDomain.indexOf('/') > -1) linkDomain = linkDomain.substring(0, linkDomain.indexOf('/'));

                            var linkDomainPieces = linkDomain.split('.');
                            if (linkDomainPieces.length > 2) {
                                linkDomain = linkDomainPieces[linkDomainPieces.length - 2] + '.' + linkDomainPieces[linkDomainPieces.length - 1];
                            }
                        }

                        // make the link suspicious unless we say otherwise
                        if (linkHref != null && linkHref.length > 0) $(link).addClass(suspiciousLinkClass);

                        // overwrite the inner html with the link href
                        // exclude mailto and tel
                        //if (linkHref != null) {
                        //    var textarea = document.createElement('textarea');
                        //    textarea.innerHTML = linkHref.replace('mailto:', '').replace('tel:', '');
                        //    $(link).html(decodeURIComponent(linkHref).replace('mailto:', '').replace('tel:', ''));
                        //}

                        // compare the link domain to the sender domain and remove the suspicious flag if they match
                        if (linkDomain != null && senderDomain.toLowerCase() == linkDomain.toLowerCase()) {
                            $(link).removeClass(suspiciousLinkClass);
                            $(link).addClass(linkClass);
                        }

                        // if the link is a mailto for the sender or recipient
                        // remove the suspicious flag and make it a regular link
                        if (linkHref != null && (linkHref.toLowerCase() == 'mailto:' + senderEmail.toLowerCase() || linkHref.toLowerCase() == 'mailto:' + recipientEmail.toLowerCase())) {
                            $(link).removeClass(suspiciousLinkClass);
                            $(link).addClass(linkClass);
                        }

                        // if the link parent has a download url, it is an attachment
                        // move the suscpicious flag to the parent
                        if (linkParent != null && (linkParent.attributes.hasOwnProperty('download_url') || $(linkParent).hasClass(attachmentParentClass))) {
                            $(link).removeClass(suspiciousLinkClass);
                            $(linkParent).addClass(suspiciousAttachmentClass);
                            suspiciousAttachmentFound = true; // all attachments are suspicious
                        }


                        // did we find something suspicious
                        if ($(link).hasClass(suspiciousLinkClass)) {
                            //suspiciousLinkFound = true;
                        }

                        // replace the link with a span
                        // include the class names if the link is suspicious and the information looks like a link (suspicious link)
                        // or, include the class names if the link isn't suspicious and the information looks like a link (ok link)
                        // else don't include the class names
                        //var test = $(link).text().indexOf('www.');
                        $(link).replaceWith(function () {
                            if ($(this).hasClass(suspiciousLinkClass) && (textLooksLikeALink(linkHref, $(this).text()) || linkHref.indexOf('mailto:') > -1 || linkHref.indexOf('tel:') > -1)) {
                                suspiciousLinkFound = true;
                                log('suspicious link html: ' + $(link).html());
                                return '<span class="' + $(this).attr('class') + '">' + $(this).html() + '</span>';
                            }
                            else if (textLooksLikeALink(linkHref, $(this).text())) {
                                return '<span class="' + $(this).attr('class') + '">' + $(this).html() + '</span>';
                            }
                            else {
                                //log('link text: ' + $(this).text());
                                return '<span>' + $(this).html() + '</span>';
                            }
                        });
                    }
                }


                // flag the email body depending on what we found above
                var emailBodyElement = $(emailBlock).find(emailBodyElementSelector);
                if (emailBodyElement != null) {
                    if (!$(emailBodyElement).hasClass(suspiciousEmailBodyClass) && !$(emailBodyElement).hasClass(emailBodyClass)) {
                        if (suspiciousLinkFound) {
                            $(emailBodyElement).addClass(suspiciousEmailBodyClass);
                            $(emailBodyElement).prepend('<div class="fishhook-suspicious-email-body-message"><span>Suspicious links or information found!</span></div>')
                        }
                        else {
                            $(emailBodyElement).addClass(emailBodyClass);
                            $(emailBodyElement).prepend('<div class="fishhook-email-body-message"><span>No suspicious links found!</span></div>')
                        }
                    }
                }


                // if there is an attachment, set a reminder to check it
                if ($(emailBlock).find('.' + suspiciousAttachmentClass).length > 0) {
                    var attachmentsArea = $(emailBlock).find(attachmentsAreaSelector);
                    if (attachmentsArea != null && attachmentsArea.length > 0) {
                        for (var iAttachmentsArea = 0; iAttachmentsArea < attachmentsArea.length; iAttachmentsArea++) {
                            var area = attachmentsArea[iAttachmentsArea];
                            if ($(emailBlock).find('span.fishhook-reminder-attachments').length == 0) {
                                $(area.parentElement).prepend('<span class="fishhook-reminder-attachments">** Make sure the attachment\'s extension (.jpg, .png, etc) is familiar and expected. **</span>');
                            }
                        }
                    }
                }


                // set a reminder to check the email from address
                if (senderEmailBlock != null && ($(senderEmailBlock).find('span.fishhook-reminder-sender-address').length == 0 && $(senderEmailBlock).find('span.fishhook-reminder-sender-address-suspicious').length == 0)) {
                    if (suspiciousLinkFound || suspiciousAttachmentFound) {
                        $(senderEmailBlock).prepend('<span class="fishhook-reminder-sender-address-suspicious">** Make sure the email address below is from who you expect. **</span>');
                    }
                    else {
                        $(senderEmailBlock).prepend('<span class="fishhook-reminder-sender-address">** Make sure the email address below is from who you expect. **</span>');
                    }
                }

            }
        }
    }



    processOpenEmailSections();

    // listen to the open email section click and run the processing again
    $(emailHeaderSelector).click(processOpenEmailSections);

});