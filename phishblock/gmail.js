chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {



    // gmail element selectors
    var emailHeaderSelector = '.kv',
        hiddenEmailHeaderSelector = '.kQ',
        emailBlockSelector = 'div.gs',
        senderElementSelector = 'h3 span.gD',
        recipientElementMeSelector = 'span.hb span.g2:contains("me")',
        recipientElementSelector = 'span.hb span.g2',
        linkSelector = 'a',
        calendarBlockLinkSelector = '.aHl a',
        headerBlockLinkSelector = '.iv a', // header could be gE/iv/gt
        spanBlockLinkSelector = '.acS a',
        trimmedContentSelector = '.ajR',
        trimmedContentLinkSelector = '.adL:hidden a',
        attachmentParentClass = 'aZo',
        emailBodyElementSelector = 'div.a3s',
        attachmentsAreaSelector = 'div>:contains("Attachments area"), div>:contains(" Attachments")'

    // phishblock classes
    var suspiciousLinkClass = 'phishblock-suspicious-link',
        linkClass = 'phishblock-link',
        suspiciousAttachmentClass = 'phishblock-suspicious-attachment',
        suspiciousEmailBodyClass = 'phishblock-suspicious-email-body',
        emailBodyClass = 'phishblock-email-body',
        suspiciousBodyMessageClass = 'phishblock-suspicious-email-body-message',
        bodyMessageClass = 'phishblock-email-body-message',
        suspiciousAttachmentMessageClass = 'phishblock-reminder-attachments',
        suspiciousSenderMessageClass = 'phishblock-reminder-sender-address-suspicious',
        senderMessageClass = 'phishblock-reminder-sender-address';

    // phishblock messages
    var suspiciousBodyMessageHtml = '<div class="' + suspiciousBodyMessageClass + '"><span>Suspicious links or information found!</span></div>',
        bodyMessageHtml = '<div class="' + bodyMessageClass + '"><span>No suspicious links found!</span></div>',
        suspiciousAttachmentMessageHtml = '<span class="' + suspiciousAttachmentMessageClass + '">** Make sure the attachment\'s extension (.jpg, .png, etc) is familiar and expected. **</span>',
        suspiciousSenderMessageHtml = '<span class="' + suspiciousSenderMessageClass  + '">** Make sure the email address below is from who you expect. **</span>',
        senderMessageHtml = '<span class="' + senderMessageClass + '">** Make sure the email address below is from who you expect. **</span>';



    // helpful functions
    function log(message) {
        console.log(message);
    }
    function textLooksLikeALink(url, text) {
        if (text == null || text.length == 0) {
            log('text looks like a link: false; no text');
            return false;
        }

        var urlRegex = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
        var looksLikeALink = urlRegex.test(text)
            || text.indexOf('www.') > -1 || text.indexOf('.com') > -1
            || text.indexOf('.net') > -1 || text.indexOf('.org') > -1
            || text.indexOf('.co') > -1 ||
            (url.indexOf(text) > -1 && text.indexOf('.') > -1);

        log('text looks like a link: ' + looksLikeALink + '; text: ' + text);
        return looksLikeALink;
    }



    // MAIN PROCESSING FUNCTION
    function processOpenEmailSections() {
        log('processing email blocks');
        var emailBlocks = $(emailBlockSelector);
        if (emailBlocks != null && emailBlocks.length > 0) {
            for (var iBlocks = 0; iBlocks < emailBlocks.length; iBlocks++) {
                var emailBlock = emailBlocks[iBlocks],
                    emailBodyElement = $(emailBlock).find(emailBodyElementSelector);
                log('processing email block ' + (iBlocks + 1));


                var senderEmailBlock = null,
                    senderEmail = null,
                    senderDomain = null,
                    senderSubdomain = null,
                    recipientEmail = null,
                    suspiciousLinkFound = false,
                    suspiciousAttachmentFound = false;


                // sender info and area selection
                log('finding sender info');
                var senderElement = $(emailBlock).find(senderElementSelector);
                if (senderElement != null && senderElement.length > 0 && senderElement[0].attributes.hasOwnProperty('email')) {
                    senderEmail = senderElement[0].attributes['email'].value;
                    senderEmailBlock = senderElement[0].parentElement;
                    log('sender email: ' + senderEmail);


                    if (senderEmail.indexOf('@') > -1) {
                        senderDomain = senderSubdomain = senderEmail.substring(senderEmail.indexOf('@') + 1);
                        var domainPieces = senderDomain.split('.');
                        if (domainPieces.length > 2) {
                            senderDomain = domainPieces[domainPieces.length - 2] + '.' + domainPieces[domainPieces.length - 1];
                        }
                    }
                    log('sender domain: ' + senderDomain);
                }


                // recipient info
                log('finding recipient info');
                var recipientElementMe = $(emailBlock).find(recipientElementMeSelector);
                var recipientElement = $(emailBlock).find(recipientElementSelector); // in case I'm sending the email
                if (recipientElementMe != null && recipientElementMe.length == 1) recipientElement = recipientElementMe;
                if (recipientElement != null && recipientElement.length > 0 && recipientElement[0].attributes.hasOwnProperty('email')) {
                    recipientEmail = recipientElement[0].attributes['email'].value;
                    log('recipient email: ' + recipientEmail);
                }


                // process each of the links in the email block
                var linksInBlock = $(emailBlock).find(linkSelector)
                    .not($(emailBlock).find(calendarBlockLinkSelector))
                    .not($(emailBlock).find(headerBlockLinkSelector))
                    .not($(emailBlock).find(spanBlockLinkSelector))
                    .not($(emailBlock).find(trimmedContentLinkSelector));
                if (linksInBlock != null && linksInBlock.length > 0) {
                    log('processing links');
                    for (var iLink = 0; iLink < linksInBlock.length; iLink++) {
                        var link = linksInBlock[iLink],
                            linkHref = link.href,
                            linkDomain = null,
                            linkParent = link.parentElement;

                        console.log('processing link: ' + linkHref);

                        // the link domain
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
                        }


                        // replace the link with a span (attachments stay as links)
                        // include the class names if the link looks like a link
                        $(link).replaceWith(function () {
                            var looksLikeAlink = textLooksLikeALink(linkHref, $(this).text());
                            if ($(this).hasClass(suspiciousLinkClass) && (looksLikeAlink || linkHref.indexOf('mailto:') > -1 || linkHref.indexOf('tel:') > -1)) {
                                log('suspicious link html: ' + $(link).html());
                                return '<span class="' + $(this).attr('class') + '">' + $(this).html() + '</span>';
                            }
                            else if (looksLikeAlink) {
                                log('regular link html: ' + $(link).html());
                                return '<span class="' + $(this).attr('class') + '">' + $(this).html() + '</span>';
                            }
                            else {
                                return '<span>' + $(this).html() + '</span>';
                            }
                        });
                    }
                }



                // what suspicious stuff did we find?
                if (emailBodyElement != null && $(emailBodyElement).find('.' + suspiciousLinkClass).not(':hidden').length > 0) {
                    log('suspicious links found!');
                    suspiciousLinkFound = true;
                }
                if ($(emailBlock).find('.' + suspiciousAttachmentClass).not(':hidden').length > 0) {
                    log('suspicious attachments found!');
                    suspiciousAttachmentFound = true;
                }



                // clear previously set header and body classes/messages before we set them
                // this allows us to run processing multiple times (expanding hidden sections, for example)
                if (emailBodyElement != null) {
                    $(emailBodyElement).removeClass(suspiciousEmailBodyClass);
                    $(emailBodyElement).removeClass(emailBodyClass);
                }
                $(emailBlock).find('.' + suspiciousBodyMessageClass).remove();
                $(emailBlock).find('.' + bodyMessageClass).remove();
                $(emailBlock).find('.' + suspiciousSenderMessageClass).remove();
                $(emailBlock).find('.' + senderMessageClass).remove();
                


                // set the email body class and message
                log('flagging email body');
                if (emailBodyElement != null) {
                    if (!$(emailBodyElement).hasClass(suspiciousEmailBodyClass) && !$(emailBodyElement).hasClass(emailBodyClass)) {
                        if (suspiciousLinkFound) {
                            $(emailBodyElement).addClass(suspiciousEmailBodyClass);
                            $(emailBodyElement).prepend(suspiciousBodyMessageHtml);
                        }
                        else {
                            $(emailBodyElement).addClass(emailBodyClass);
                            $(emailBodyElement).prepend(bodyMessageHtml);
                        }
                    }
                }


                // set a reminder to check attachments
                log('flagging attachment section');
                if ($(emailBlock).find('.' + suspiciousAttachmentClass).length > 0) {
                    var attachmentsArea = $(emailBlock).find(attachmentsAreaSelector);
                    if (attachmentsArea != null && attachmentsArea.length > 0) {
                        for (var iAttachmentsArea = 0; iAttachmentsArea < attachmentsArea.length; iAttachmentsArea++) {
                            var area = attachmentsArea[iAttachmentsArea];
                            if ($(emailBlock).find('.' + suspiciousAttachmentMessageClass).length == 0) {
                                $(area.parentElement).prepend(suspiciousAttachmentMessageHtml);
                            }
                        }
                    }
                }


                // set a reminder to check the sender address
                log('flagging sender block');
                if (senderEmailBlock != null && ($(senderEmailBlock).find('.' + senderMessageClass).length == 0 && $(senderEmailBlock).find('.' + suspiciousSenderMessageClass).length == 0)) {
                    if (suspiciousLinkFound || suspiciousAttachmentFound) {
                        $(senderEmailBlock).prepend(suspiciousSenderMessageHtml);
                    }
                    else {
                        $(senderEmailBlock).prepend(senderMessageHtml);
                    }
                }


                log('finished processing email block');
            }
        }
    }
    // END MAIN PROCESSING FUNCTION


    log('attaching phishblock');
    processOpenEmailSections();


    // listen to the open email section click
    $(emailHeaderSelector).on('click.phishblock-emailHeader', function () {
        setTimeout(processOpenEmailSections, 250);
    });


    // listen to the expand/collapse hidden content click
    function expandOrCollapseHiddenContentClickHandler() {
        setTimeout(processOpenEmailSections, 250);
    };
    $(trimmedContentSelector).on('click.phishblock-trimmedContent', expandOrCollapseHiddenContentClickHandler);


    // listen to the open middle collapsed emails click
    // this part is convoluted
    $(hiddenEmailHeaderSelector).click(function () {
        // timeout because the middle email sections generate slowly
        setTimeout(function () {

            // remove the old click handlers and add new ones
            $(emailHeaderSelector).off('click.phishblock-emailHeader');
            $(emailHeaderSelector).on('click.phishblock-emailHeader', function () {
                // another timer because the sections haven't been rendered yet
                setTimeout(function () {
                    processOpenEmailSections();

                    // also need to listen to trimmed content expander
                    $(trimmedContentSelector).off('click.phishblock-trimmedContent');
                    $(trimmedContentSelector).on('click.phishblock-trimmedContent', expandOrCollapseHiddenContentClickHandler);

                }, 250);
            });
        }, 250);
    });


});