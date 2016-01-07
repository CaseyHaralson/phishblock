
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {

    function processOpenEmailSections() {
        //console.log('processing gmail page');

        var emailBlocks = $('div.gs');
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
                var senderElement = $(emailBlock).find('h3 span.gD');
                if (senderElement != null && senderElement.length == 1 && senderElement[0].attributes.hasOwnProperty('email')) {
                    var senderEmail = senderElement[0].attributes['email'].value;
                    senderEmailBlock = senderElement[0].parentElement;
                }


                // lets find the sender's domain
                if (senderEmail != null && senderEmail.indexOf('@') > -1) {
                    senderDomain = senderSubdomain = senderEmail.substring(senderEmail.indexOf('@') + 1);

                    var domainPieces = senderDomain.split('.');
                    if (domainPieces.length > 2) {
                        senderDomain = domainPieces[domainPieces.length - 2] + '.' + domainPieces[domainPieces.length - 1];
                    }
                }


                // lets find the recipient
                var recipientElementMe = $(emailBlock).find('span.hb span.g2:contains("me")');
                var recipientElement = $(emailBlock).find('span.hb span.g2'); // in case I'm sending the email
                if (recipientElementMe != null && recipientElementMe.length == 1) recipientElement = recipientElementMe;
                if (recipientElement != null && recipientElement.length > 0 && recipientElement[0].attributes.hasOwnProperty('email')) {
                    var recipientEmail = recipientElement[0].attributes['email'].value;
                }


                // lets look at all the links in the email block (skip links inside calendar block and header)
                // and make sure it comes from the correct domain
                // or that it's a mailto link to the sender or recipient
                var linksInBlock = $(emailBlock).find('a').not($(emailBlock).find('.aHl a')).not($(emailBlock).find('.iv a')); // header could be gE/iv/gt
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
                        if (linkHref != null && linkHref.length > 0) $(link).addClass('fishhook-suspicious-link');

                        // compare the link domain to the sender domain and remove the suspicious flag if they match
                        if (linkDomain != null && senderDomain.toLowerCase() == linkDomain.toLowerCase()) {
                            $(link).removeClass('fishhook-suspicious-link');
                            $(link).addClass('fishhook-link');
                        }

                        // if the link is a mailto for the sender or recipient
                        // remove the suspicious flag and make it a regular link
                        if (linkHref != null && (linkHref.toLowerCase() == 'mailto:' + senderEmail.toLowerCase() || linkHref.toLowerCase() == 'mailto:' + recipientEmail.toLowerCase())) {
                            $(link).removeClass('fishhook-suspicious-link');
                            $(link).addClass('fishhook-link');
                        }

                        // if the link parent has a download url, it is an attachment
                        // move the suscpicious flag to the parent
                        if (linkParent != null && (linkParent.attributes.hasOwnProperty('download_url') || $(linkParent).hasClass('aZo'))) {
                            $(link).removeClass('fishhook-suspicious-link');
                            $(linkParent).addClass('fishhook-suspicious-attachment');
                            suspiciousAttachmentFound = true; // all attachments are suspicious
                        }


                        // did we find something suspicious
                        if ($(link).hasClass('fishhook-suspicious-link')) {
                            suspiciousLinkFound = true;
                        }
                    }
                }


                // flag the email body depending on what we found above
                var emailBodyElement = $(emailBlock).find('div.a3s');
                if (emailBodyElement != null) {
                    if (!$(emailBodyElement).hasClass('fishhook-suspicious-email-body') && !$(emailBodyElement).hasClass('fishhook-email-body')) {
                        if (suspiciousLinkFound) {
                            $(emailBodyElement).addClass('fishhook-suspicious-email-body');
                            $(emailBodyElement).prepend('<div class="fishhook-suspicious-email-body-message"><span>Suspicious links found!</span></div>')
                        }
                        else {
                            $(emailBodyElement).addClass('fishhook-email-body');
                            $(emailBodyElement).prepend('<div class="fishhook-email-body-message"><span>No suspicious links found!</span></div>')
                        }
                    }
                }


                // if there is an attachment, set a reminder to check it
                if ($(emailBlock).find('span.fishhook-suspicious-attachment').length > 0) {
                    var attachmentsArea = $(emailBlock).find('div>:contains("Attachments area"), div>:contains(" Attachments")');
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
    $('.kv').click(processOpenEmailSections);

});