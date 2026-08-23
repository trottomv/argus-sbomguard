(function () {
    'use strict';

    document.addEventListener('alpine:init', function () {
        Alpine.data('vulnPage', function () {
            return {
                severity: '',
                project: '',
                service: '',
                detail: { cve_id: '', severity: '', cvss: '', cvss_vector: '', summary: '', published: '', urls: [], affected: [], fixed: [] },
                init() {
                    this.severity = this.$el.dataset.severity || '';
                    this.project = this.$el.dataset.project || '';
                    this.service = this.$el.dataset.service || '';
                    this.reloadParams = this.$el.dataset.reloadParams || '';
                },
                get filtersActive() {
                    return this.severity || this.project || this.service;
                },
                openDetail(event) {
                    this.detail = JSON.parse(event.currentTarget.getAttribute('data-detail'));
                    document.getElementById('detail_modal').showModal();
                },
                reloadFilters() {
                    htmx.ajax('GET', '/vulnerabilities?severity=' + this.severity + '&project_id=' + this.project + '&service_id=' + this.service + '&' + this.reloadParams, { target: '#vuln-page', swap: 'outerHTML' });
                },
                clearFilters() {
                    this.severity = '';
                    this.project = '';
                    this.service = '';
                    this.reloadFilters();
                },
                onProjectChange() {
                    this.service = '';
                    this.reloadFilters();
                }
            };
        });

        Alpine.data('sbomPage', function () {
            return {
                sbomDelId: null,
                sbomDelVer: '',
                project: '',
                service: '',
                init() {
                    this.project = this.$el.dataset.project || '';
                    this.service = this.$el.dataset.service || '';
                    this.reloadParams = this.$el.dataset.reloadParams || '';
                },
                get filtersActive() {
                    return this.project || this.service;
                },
                reloadFilters() {
                    htmx.ajax('GET', '/sboms?project_id=' + this.project + '&service_id=' + this.service + '&' + this.reloadParams, { target: '#sbom-page', swap: 'outerHTML' });
                },
                clearFilters() {
                    this.project = '';
                    this.service = '';
                    this.reloadFilters();
                },
                onProjectChange() {
                    this.service = '';
                    this.reloadFilters();
                },
                openDeleteSbom(id, ver) {
                    this.sbomDelId = id;
                    this.sbomDelVer = ver;
                    document.getElementById('delete_sbom_modal').showModal();
                },
                confirmDelete() {
                    fetch('/api/v1/sboms/' + this.sbomDelId, { method: 'DELETE' }).then(function (r) {
                        if (r.ok) window.location.reload();
                    });
                    document.getElementById('delete_sbom_modal').close();
                }
            };
        });

        Alpine.data('projectsPage', function () {
            return {
                delId: null,
                delName: '',
                editId: null,
                name: '',
                description: '',
                repo_url: '',
                platform: '',
                openNew() {
                    this.editId = null;
                    this.name = '';
                    this.description = '';
                    this.repo_url = '';
                    this.platform = '';
                    document.getElementById('my_modal_1').showModal();
                },
                openEdit(event) {
                    var el = event.currentTarget;
                    this.editId = el.dataset.id;
                    this.name = el.dataset.name;
                    this.description = el.dataset.description;
                    this.repo_url = el.dataset.repoUrl;
                    this.platform = el.dataset.platform;
                    document.getElementById('my_modal_1').showModal();
                },
                submit() {
                    var url = this.editId ? '/api/v1/projects/' + this.editId : '/api/v1/projects';
                    var method = this.editId ? 'PATCH' : 'POST';
                    var body = { name: this.name };
                    if (this.description) body.description = this.description;
                    if (this.repo_url) body.repo_url = this.repo_url;
                    if (this.platform) body.platform = this.platform;
                    fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(function (r) {
                        if (r.ok) window.location.reload();
                    });
                },
                openDelete(event) {
                    this.delId = event.currentTarget.dataset.id;
                    this.delName = event.currentTarget.dataset.name;
                    document.getElementById('delete_modal').showModal();
                },
                confirmDelete() {
                    fetch('/api/v1/projects/' + this.delId, { method: 'DELETE' }).then(function (r) {
                        if (r.ok) window.location.reload();
                    });
                }
            };
        });

        Alpine.data('projectDetail', function () {
            return {
                sbomDelId: null,
                sbomDelVer: '',
                svcDelId: null,
                svcDelName: '',
                svcError: '',
                projectId: '',
                detail: { cve_id: '', severity: '', cvss: '', cvss_vector: '', summary: '', published: '', urls: [], affected: [], fixed: [], dependency: '' },
                init() {
                    this.projectId = this.$el.dataset.projectId || '';
                },
                confirmDeleteProject() {
                    fetch('/api/v1/projects/' + this.projectId, { method: 'DELETE' }).then((r) => {
                        if (r.ok) window.location = '/projects';
                    });
                    document.getElementById('delete_project_modal').close();
                },
                openDetail(event) {
                    this.detail = JSON.parse(event.currentTarget.getAttribute('data-detail'));
                    document.getElementById('detail_modal').showModal();
                },
                openDeleteSbom(id, ver) {
                    this.sbomDelId = id;
                    this.sbomDelVer = ver;
                    document.getElementById('delete_sbom_modal').showModal();
                },
                confirmDeleteSbom() {
                    fetch('/api/v1/sboms/' + this.sbomDelId, { method: 'DELETE' }).then(function (r) {
                        if (r.ok) window.location.reload();
                    });
                    document.getElementById('delete_sbom_modal').close();
                },
                openDeleteService(event) {
                    this.svcDelId = event.currentTarget.dataset.id;
                    this.svcDelName = event.currentTarget.dataset.name;
                    document.getElementById('delete_service_modal').showModal();
                },
                confirmDeleteService() {
                    this.svcError = '';
                    fetch('/api/v1/services/' + this.svcDelId, { method: 'DELETE' }).then((r) => {
                        if (r.ok) {
                            window.location.reload();
                        } else {
                            r.json().then((j) => {
                                this.svcError = j.detail || 'Failed to delete service';
                            });
                        }
                    }).catch(() => {
                        this.svcError = 'Network error';
                    });
                }
            };
        });

        Alpine.data('settingsPage', function () {
            return {
                keyId: null,
                keyLabel: '',
                editAlertRuleId: null,
                alertProject: '',
                alertSeverity: 'high',
                alertType: 'email',
                alertEnabled: true,
                delAlertRuleId: null,
                createdKey: '',
                showCreatedKey: false,
                newKeyLabel: '',
                reload() {
                    window.location.reload();
                },
                copyKey() {
                    navigator.clipboard.writeText(this.createdKey).catch(function () {});
                },
                openGenKey() {
                    this.newKeyLabel = '';
                    document.getElementById('gen_key_modal').showModal();
                },
                submitKey() {
                    fetch('/settings/api-keys', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ label: this.newKeyLabel })
                    }).then((r) => r.json()).then((data) => {
                        this.createdKey = data.key;
                        this.showCreatedKey = true;
                        document.getElementById('gen_key_modal').close();
                    });
                },
                openRevoke(event) {
                    this.keyId = event.currentTarget.dataset.id;
                    this.keyLabel = event.currentTarget.dataset.label;
                    document.getElementById('revoke_key_modal').showModal();
                },
                confirmRevoke() {
                    fetch('/settings/api-keys/' + this.keyId, { method: 'DELETE' }).then(function (r) {
                        if (r.ok) window.location.reload();
                    });
                    document.getElementById('revoke_key_modal').close();
                },
                openNewAlertRule() {
                    this.editAlertRuleId = null;
                    this.alertProject = '';
                    this.alertSeverity = 'high';
                    this.alertType = 'email';
                    this.alertEnabled = true;
                    document.getElementById('alert_modal').showModal();
                },
                openEditAlertRule(event) {
                    var el = event.currentTarget;
                    this.editAlertRuleId = el.dataset.id;
                    this.alertProject = el.dataset.project;
                    this.alertSeverity = el.dataset.severity;
                    this.alertType = el.dataset.type;
                    this.alertEnabled = el.dataset.enabled === 'true';
                    document.getElementById('alert_modal').showModal();
                },
                submitAlertRule() {
                    var url = this.editAlertRuleId ? '/api/v1/alert-rules/' + this.editAlertRuleId : '/api/v1/alert-rules';
                    var method = this.editAlertRuleId ? 'PATCH' : 'POST';
                    var body = {
                        project_id: this.alertProject,
                        severity_threshold: this.alertSeverity,
                        notification_type: this.alertType,
                        enabled: this.alertEnabled
                    };
                    fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(function (r) {
                        if (r.ok) window.location.reload();
                    });
                },
                openDeleteAlertRule(event) {
                    this.delAlertRuleId = event.currentTarget.dataset.id;
                    document.getElementById('delete_alert_modal').showModal();
                },
                confirmDeleteAlertRule() {
                    fetch('/api/v1/alert-rules/' + this.delAlertRuleId, { method: 'DELETE' }).then(function (r) {
                        if (r.ok) window.location.reload();
                    });
                    document.getElementById('delete_alert_modal').close();
                }
            };
        });

        Alpine.data('refreshButton', function () {
            return {
                refreshing: false,
                refresh() {
                    this.refreshing = true;
                    fetch('/refresh-snapshots', { method: 'POST' })
                        .then((r) => {
                            if (r.ok) setTimeout(function () { window.location.reload(); }, 2500);
                            else this.refreshing = false;
                        })
                        .catch(() => {
                            this.refreshing = false;
                        });
                }
            };
        });
    });
})();
