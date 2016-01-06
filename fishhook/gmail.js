
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
                    somethingSuspiciousFound = false;


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
                var recipientElement = $(emailBlock).find('span.hb span.g2');
                if (recipientElement != null && recipientElement.length > 0 && recipientElement[recipientElement.length - 1].attributes.hasOwnProperty('email')) {
                    var recipientEmail = recipientElement[recipientElement.length - 1].attributes['email'].value;
                }


                // lets look at all the links in the email block
                // and make sure it comes from the correct domain
                // or that it's a mailto link to the sender or recipient
                var linksInBlock = $(emailBlock).find('a');
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
                        if (linkDomain != null && senderDomain === linkDomain) {
                            $(link).removeClass('fishhook-suspicious-link');
                        }

                        // if the link is a mailto for the sender or recipient
                        // remove the suspicious flag
                        if (linkHref != null && (linkHref == 'mailto:' + senderEmail || linkHref == 'mailto:' + recipientEmail)) {
                            $(link).removeClass('fishhook-suspicious-link');
                        }

                        // if the link parent has a download url, it is an attachment
                        // move the suscpicious flag to the parent
                        if (linkParent != null && linkParent.attributes.hasOwnProperty('download_url')) {
                            $(link).removeClass('fishhook-suspicious-link');
                            $(linkParent).addClass('fishhook-suspicious-attachment');
                        }


                        // did we find something suspicious
                        if ($(link).hasClass('fishhook-suspicious-link')) {
                            somethingSuspiciousFound = true;
                        }
                    }
                }


                // flag the email body depending on what we found above
                var emailBodyElement = $(emailBlock).find('div.a3s');
                if (emailBodyElement != null) {
                    if (somethingSuspiciousFound) $(emailBodyElement).addClass('fishhook-suspicious-email-body');
                    else $(emailBodyElement).addClass('fishhook-email-body');
                }


                // set a reminder to check the email from address
                if (senderEmailBlock != null && $(senderEmailBlock).find('span.fishhook-reminder').length == 0) {
                    $(senderEmailBlock).prepend('<span class="fishhook-reminder">Make sure the email address looks good.</span>');
                }


                // if there is an attachment, set a reminder to check it
                if ($(emailBlocks).find('span.fishhook-suspicious-attachment').length > 0) {
                    var attachmentsArea = $(emailBlocks).find('div>:contains("Attachments area")');
                    if (attachmentsArea != null && attachmentsArea.length > 0) {
                        for (var iAttachmentsArea = 0; iAttachmentsArea < attachmentsArea.length; iAttachmentsArea++) {
                            var area = attachmentsArea[iAttachmentsArea];
                            if ($(area.parentElement).find('span.fishhook-reminder').length == 0) {
                                $(area.parentElement).prepend('<span class="fishhook-reminder">Make sure the attachments are ok file types.');
                            }
                        }
                    }
                }

            }
        }
    }



    processOpenEmailSections();

    // listen to the open email section click and run the processing again
    $('.kv').click(processOpenEmailSections);

});