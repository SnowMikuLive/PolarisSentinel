// Shared by Rules/Create and Rules/Edit.
// "Any" clears the paired input (empty IP / 0 port); "Manual" restores editing.
document.querySelectorAll('.ip-mode, .port-mode').forEach(function (mode) {
    var input = document.getElementById(mode.dataset.target);
    function sync() {
        var any = mode.value === 'any';
        input.readOnly = any;
        input.classList.toggle('bg-light', any);
        if (any) {
            input.value = '';
        }
    }
    mode.addEventListener('change', sync);
    sync();
});
