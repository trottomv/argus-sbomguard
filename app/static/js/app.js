(function () {
    'use strict';

    document.addEventListener('click', function (event) {
        var target = event.target.closest('[data-close-modal]');
        if (target) {
            var modal = document.getElementById(target.getAttribute('data-close-modal'));
            if (modal && typeof modal.close === 'function') {
                modal.close();
            }
            return;
        }

        target = event.target.closest('[data-open-modal]');
        if (target) {
            var resetSel = target.getAttribute('data-reset-form');
            if (resetSel) {
                var form = document.querySelector(resetSel);
                if (form && typeof form.reset === 'function') {
                    form.reset();
                }
            }
            var toOpen = document.getElementById(target.getAttribute('data-open-modal'));
            if (toOpen && typeof toOpen.showModal === 'function') {
                toOpen.showModal();
            }
            return;
        }

        target = event.target.closest('[data-toggle-mobile-menu]');
        if (target) {
            document.getElementById('mobile-menu').classList.toggle('hidden');
            return;
        }

        target = event.target.closest('[data-close-mobile-menu]');
        if (target) {
            document.getElementById('mobile-menu').classList.add('hidden');
            return;
        }

        target = event.target.closest('[data-copy]');
        if (target) {
            var text = target.getAttribute('data-copy');
            navigator.clipboard.writeText(text);
            target.classList.add('badge-primary');
        }
    });

    document.body.addEventListener('htmx:afterRequest', function (event) {
        if (event.target.id === 'upload-form' && event.detail.successful) {
            var modal = document.getElementById('upload_modal');
            if (modal && typeof modal.close === 'function') {
                modal.close();
            }
            window.location.reload();
        }
    });
})();
