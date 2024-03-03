$(document).ready(function () {
    const VERIFY_URL = $('meta[name="verify-url"]').attr('content');
    const FORM_ERROR_MESSAGE = $('meta[name="form-error-message"]').attr('content');

    $('form').submit(function (event) {
        event.preventDefault();
        const postData = $(this).serialize();

        $.post(VERIFY_URL, postData, function (response) {
            if (response.redirect_url) {
                alert(response.message);
                window.location.href = response.redirect_url;
            } else {
                alert(response.message);
            }
        }, 'json').fail(function () {
            alert(FORM_ERROR_MESSAGE);
        });
    });
});
