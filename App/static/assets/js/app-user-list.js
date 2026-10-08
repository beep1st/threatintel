'use strict';

// Utility function to get CSRF token
function getCsrfToken() {
  return document.querySelector('input[name="csrfmiddlewaretoken"]').value;
}

// Utility function to show Bootstrap alert
function showAlert(containerId, message, type) {
  var alertHtml = `<div class="alert alert-${type} alert-dismissible" role="alert">${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>`;
  $(`#${containerId}`).html(alertHtml);
  setTimeout(() => $(`#${containerId} .alert`).alert('close'), 5000);
}

// Datatable (jquery)
$(function () {
  let borderColor, bodyBg, headingColor;

  if (isDarkStyle) {
    borderColor = config.colors_dark.borderColor;
    bodyBg = config.colors_dark.bodyBg;
    headingColor = config.colors_dark.headingColor;
  } else {
    borderColor = config.colors.borderColor;
    bodyBg = config.colors.bodyBg;
    headingColor = config.colors.headingColor;
  }

  var dt_user_table = $('.datatables-users'),
    select2 = $('.select2'),
    userView = user_accounts,
    statusObj = {
      1: { title: 'credit limit under 20%', class: 'bg-label-success' },
      2: { title: 'credit limit under 40%', class: 'bg-label-info' },
      3: { title: 'credit limit under 60%', class: 'bg-label-secondary' },
      4: { title: 'credit limit under 80%', class: 'bg-label-warning' },
      5: { title: 'credit limit reached', class: 'bg-label-danger' }
    };

  if (select2.length) {
    var $this = select2;
    $this.wrap('<div class="position-relative"></div>').select2({
      placeholder: 'Select Country',
      dropdownParent: $this.parent()
    });
  }

  if (dt_user_table.length) {
    var dt_user = dt_user_table.DataTable({
      ajax: '/client_list_api/',
      columns: [
        { data: 'id' },
        { data: 'id' },
        { data: 'full_name' },
        { data: 'email' },
        { data: 'phone_number' },
        { data: 'company_name' },
        { data: 'current_balance' },
        { data: 'action' }
      ],
      columnDefs: [
        {
          className: 'control',
          searchable: false,
          orderable: false,
          responsivePriority: 2,
          targets: 0,
          render: function (data, type, full, meta) {
            return '';
          }
        },
        {
          targets: 1,
          orderable: false,
          checkboxes: {
            selectAllRender: '<input type="checkbox" class="form-check-input">'
          },
          render: function () {
            return '<input type="checkbox" class="dt-checkboxes form-check-input">';
          },
          searchable: false
        },
        {
          targets: 2,
          responsivePriority: 4,
          render: function (data, type, full, meta) {
            var $name = full['full_name'],
              $email = full['email'],
              $image = full['avatar'];
            var $output = $image
              ? '<img src="' + assetsPath + 'img/avatars/' + $image + '" alt="Avatar" class="rounded-circle">'
              : '<span class="avatar-initial rounded-circle bg-label-' + ['success', 'danger', 'warning', 'info', 'primary', 'secondary'][Math.floor(Math.random() * 6)] + '">' + (($name.match(/\b\w/g) || []).shift() || '') + (($name.match(/\b\w/g) || []).pop() || '').toUpperCase() + '</span>';
            return `
              <div class="d-flex justify-content-start align-items-center user-name">
                <div class="avatar-wrapper">
                  <div class="avatar avatar-sm me-4">${$output}</div>
                </div>
                <div class="d-flex flex-column">
                  <a href="${userView}${full['id']}" class="text-heading text-truncate"><span class="fw-medium">${$name}</span></a>
                  <small>${$email}</small>
                </div>
              </div>`;
          }
        },
        {
          targets: 3,
          render: function (data, type, full, meta) {
            var $email = full['email'];
            return '<span class="text-heading">' + $email + '</span>';
          }
        },
        {
          targets: 4,
          render: function (data, type, full, meta) {
            var $phone = full['phone_number'];
            return '<span class="text-heading">' + $phone + '</span>';
          }
        },
        {
          targets: 5,
          render: function (data, type, full, meta) {
            var $company = full['company_name'];
            return '<span class="text-heading">' + $company + '</span>';
          }
        },
        {
          targets: 6,
          render: function (data, type, full, meta) {
            var $balance = full['current_balance'],
                $credit_limit = full['credit_limit'],
                $status = $balance / $credit_limit * 100 < 20 ? 1 : $balance / $credit_limit * 100 < 40 ? 2 : $balance / $credit_limit * 100 < 60 ? 3 : $balance / $credit_limit * 100 < 80 ? 4 : 5;
            return '<span class="badge ' + statusObj[$status].class + '">' + $balance + '</span>';
          }
        },
        {
          targets: -1,
          title: 'Actions',
          searchable: false,
          orderable: false,
          render: function (data, type, full, meta) {
            // Ensure note is string, default to empty string if undefined or null
            var note = full['note'] ? String(full['note']).replace(/"/g, '&quot;') : '';
            return `
              <div class="d-flex align-items-center">
                <a href="javascript:;" class="btn btn-icon btn-text-secondary waves-effect waves-light rounded-pill edit-record" 
                   data-client-id="${full['id']}" 
                   data-name="${full['full_name'] ? String(full['full_name']).replace(/"/g, '&quot;') : ''}" 
                   data-email="${full['email'] ? String(full['email']).replace(/"/g, '&quot;') : ''}" 
                   data-phone="${full['phone_number'] ? String(full['phone_number']).replace(/"/g, '&quot;') : ''}" 
                   data-company="${full['company_name'] ? String(full['company_name']).replace(/"/g, '&quot;') : ''}" 
                   data-credit-limit="${full['credit_limit'] || ''}" 
                   data-address="${full['address'] ? String(full['address']).replace(/"/g, '&quot;') : ''}" 
                   data-note="${note}" 
                   data-bs-toggle="modal" 
                   data-bs-target="#editUserModal">
                  <i class="ti ti-edit ti-md"></i>
                </a>
                <a href="javascript:;" class="btn btn-icon btn-text-secondary waves-effect waves-light rounded-pill delete-record" 
                   data-client-id="${full['id']}" 
                   data-bs-toggle="modal" 
                   data-bs-target="#deleteModal">
                  <i class="ti ti-trash ti-md"></i>
                </a>
                <a href="${userView}${full['id']}" class="btn btn-icon btn-text-secondary waves-effect waves-light rounded-pill">
                  <i class="ti ti-eye ti-md"></i>
                </a>
              </div>`;
          }
        }
      ],
      order: [[2, 'desc']],
      dom:
        '<"row"' +
        '<"col-md-2"<"ms-n2"l>>' +
        '<"col-md-10"<"dt-action-buttons text-xl-end text-lg-start text-md-end text-start d-flex align-items-center justify-content-end flex-md-row flex-column mb-6 mb-md-0 mt-n6 mt-md-0"fB>>' +
        '>t' +
        '<"row"' +
        '<"col-sm-12 col-md-6"i>' +
        '<"col-sm-12 col-md-6"p>' +
        '>',
      language: {
        sLengthMenu: '_MENU_',
        search: '',
        searchPlaceholder: 'Search User',
        paginate: {
          next: '<i class="ti ti-chevron-right ti-sm"></i>',
          previous: '<i class="ti ti-chevron-left ti-sm"></i>'
        }
      },
      buttons: [
  {
    extend: 'collection',
    className: 'btn btn-label-secondary dropdown-toggle mx-4 waves-effect waves-light',
    text: '<i class="ti ti-upload me-2 ti-xs"></i>Export',
    buttons: [
      {
        extend: 'print',
        text: '<i class="ti ti-printer me-2"></i>Print',
        className: 'dropdown-item',
        exportOptions: {
          columns: [1, 2, 3, 4, 5, 6],
          format: {
            body: function (inner) {
              const div = document.createElement('div');
              div.innerHTML = inner;
              const nameSpan = div.querySelector('span.fw-medium');
              return nameSpan ? nameSpan.textContent.trim() : div.textContent.trim();
            }
          }
        },
        customize: function (win) {
          $(win.document.body)
            .css('color', headingColor)
            .css('border-color', borderColor)
            .css('background-color', bodyBg);
          $(win.document.body).find('table')
            .addClass('compact')
            .css('color', 'inherit')
            .css('border-color', 'inherit')
            .css('background-color', 'inherit');
        }
      },
      {
        extend: 'csv',
        text: '<i class="ti ti-file-text me-2"></i>Csv',
        className: 'dropdown-item',
        exportOptions: {
          columns: [1, 2, 3, 4, 5, 6],
          format: {
            body: function (inner) {
              const div = document.createElement('div');
              div.innerHTML = inner;
              const nameSpan = div.querySelector('span.fw-medium');
              return nameSpan ? nameSpan.textContent.trim() : div.textContent.trim();
            }
          }
        }
      },
      {
        extend: 'excel',
        text: '<i class="ti ti-file-spreadsheet me-2"></i>Excel',
        className: 'dropdown-item',
        exportOptions: {
          columns: [1, 2, 3, 4, 5, 6],
          format: {
            body: function (inner) {
              const div = document.createElement('div');
              div.innerHTML = inner;
              const nameSpan = div.querySelector('span.fw-medium');
              return nameSpan ? nameSpan.textContent.trim() : div.textContent.trim();
            }
          }
        }
      },
      {
        extend: 'pdf',
        text: '<i class="ti ti-file-code-2 me-2"></i>Pdf',
        className: 'dropdown-item',
        exportOptions: {
          columns: [1, 2, 3, 4, 5, 6],
          format: {
            body: function (inner) {
              const div = document.createElement('div');
              div.innerHTML = inner;
              const nameSpan = div.querySelector('span.fw-medium');
              return nameSpan ? nameSpan.textContent.trim() : div.textContent.trim();
            }
          }
        }
      },
      {
        extend: 'copy',
        text: '<i class="ti ti-copy me-2"></i>Copy',
        className: 'dropdown-item',
        exportOptions: {
          columns: [1, 2, 3, 4, 5, 6],
          format: {
            body: function (inner) {
              const div = document.createElement('div');
              div.innerHTML = inner;
              const nameSpan = div.querySelector('span.fw-medium');
              return nameSpan ? nameSpan.textContent.trim() : div.textContent.trim();
            }
          }
        }
      }
    ]
  },
  {
    text: '<i class="ti ti-plus me-0 me-sm-1 ti-xs"></i><span class="d-none d-sm-inline-block">Add New User</span>',
    className: 'add-new btn btn-primary waves-effect waves-light',
    attr: {
      'data-bs-toggle': 'offcanvas',
      'data-bs-target': '#offcanvasAddUser'
    }
  }
],

      responsive: {
        details: {
          display: $.fn.dataTable.Responsive.display.modal({
            header: function (row) {
              var data = row.data();
              return 'Details of ' + data['full_name'];
            }
          }),
          type: 'column',
          renderer: function (api, rowIdx, columns) {
            var data = $.map(columns, function (col, i) {
              return col.title !== ''
                ? '<tr data-dt-row="' + col.rowIndex + '" data-dt-column="' + col.columnIndex + '">' +
                    '<td>' + col.title + ':</td> ' +
                    '<td>' + col.data + '</td>' +
                    '</tr>'
                : '';
            }).join('');
            return data ? $('<table class="table"/><tbody />').append(data) : false;
          }
        }
      },
      initComplete: function () {
        this.api()
          .columns(3)
          .every(function () {
            var column = this;
            var select = $('<select id="UserRole" class="form-select text-capitalize"><option value=""> Select Role </option></select>')
              .appendTo('.user_role')
              .on('change', function () {
                var val = $.fn.dataTable.util.escapeRegex($(this).val());
                column.search(val ? '^' + val + '$' : '', true, false).draw();
              });
            column.data().unique().sort().each(function (d, j) {
              select.append('<option value="' + d + '">' + d + '</option>');
            });
          });
        this.api()
          .columns(4)
          .every(function () {
            var column = this;
            var select = $('<select id="UserPlan" class="form-select text-capitalize"><option value=""> Select Plan </option></select>')
              .appendTo('.user_plan')
              .on('change', function () {
                var val = $.fn.dataTable.util.escapeRegex($(this).val());
                column.search(val ? '^' + val + '$' : '', true, false).draw();
              });
            column.data().unique().sort().each(function (d, j) {
              select.append('<option value="' + d + '">' + d + '</option>');
            });
          });
      }
    });

    // Handle edit button click
    dt_user_table.on('click', '.edit-record', function () {
      var $button = $(this);
      $('#edit-client-id').val($button.data('client-id'));
      $('#edit-user-fullname').val($button.data('name'));
      $('#edit-user-email').val($button.data('email'));
      $('#edit-user-contact').val($button.data('phone'));
      $('#edit-user-company').val($button.data('company'));
      $('#edit-user-credit-limit').val($button.data('credit-limit'));
      $('#edit-user-address').val($button.data('address'));
      $('#edit-user-note').val($button.data('note') || ''); // Ensure note is not undefined
      $('#editUserForm').attr('action', '/edit-client/' + $button.data('client-id') + '/');
      $('#edit-alert-container').empty();
      // Debug: Log the note value
      console.log('Note value set to:', $button.data('note'));
    });

    // Handle delete button click
    dt_user_table.on('click', '.delete-record', function () {
      var $button = $(this);
      $('#delete-client-id').val($button.data('client-id'));
      $('#deleteForm').attr('action', '/delete-client/' + $button.data('client-id') + '/');
      $('#confirmPassword').val('');
      $('#delete-alert-container').empty();
    });
  }

  setTimeout(() => {
    $('.dataTables_filter .form-control').removeClass('form-control-sm');
    $('.dataTables_length .form-select').removeClass('form-select-sm');
  }, 300);
});

// Validation & Phone mask
(function () {
  const phoneMaskList = document.querySelectorAll('.phone-mask'),
        addNewUserForm = document.getElementById('addNewUserForm'),
        editUserForm = document.getElementById('editUserForm'),
        deleteForm = document.getElementById('deleteForm');

  if (phoneMaskList) {
    phoneMaskList.forEach(function (phoneMask) {
      new Cleave(phoneMask, {
        phone: true,
        phoneRegionCode: 'PK'
      });
    });
  }

  // Add New User Form Validation
  if (addNewUserForm) {
    FormValidation.formValidation(addNewUserForm, {
      fields: {
        name: {
          validators: {
            notEmpty: { message: 'Please enter full name' }
          }
        },
        email: {
          validators: {
            notEmpty: { message: 'Please enter your email' },
            emailAddress: { message: 'The value is not a valid email address' }
          }
        },
        phone_number: {
          validators: {
            notEmpty: { message: 'Please enter your phone number' },
            regexp: { regexp: /^[3][0-9]{9}$/, message: 'Phone number must be a valid Pakistani number starting with 3' }
          }
        },
        creditLimit: {
          validators: {
            notEmpty: { message: 'Please enter credit limit' },
            numeric: { message: 'Credit limit must be a number' }
          }
        },
        companyName: {
          validators: { notEmpty: { message: 'Please enter company name' } }
        }
      },
      plugins: {
        trigger: new FormValidation.plugins.Trigger(),
        bootstrap5: new FormValidation.plugins.Bootstrap5({
          eleValidClass: '',
          rowSelector: function (field, ele) { return '.mb-6'; }
        }),
        submitButton: new FormValidation.plugins.SubmitButton(),
        autoFocus: new FormValidation.plugins.AutoFocus()
      }
    }).on('core.form.valid', function () {
      $.ajax({
        url: addNewUserForm.action,
        type: 'POST',
        data: new FormData(addNewUserForm),
        processData: false,
        contentType: false,
        headers: { 'X-CSRFToken': getCsrfToken() },
        success: function (response) {
          if (response.status === 'success') {
            showAlert('add-alert-container', response.message, 'success');
            $('#offcanvasAddUser').offcanvas('hide');
            dt_user_table.DataTable().ajax.reload(null, false);
            addNewUserForm.reset();
          } else {
            showAlert('add-alert-container', response.message, 'danger');
          }
        },
        error: function (xhr) {
          showAlert('add-alert-container', xhr.responseJSON ? xhr.responseJSON.message : 'An error occurred.', 'danger');
        }
      });
    });
  }

  // Edit User Form Validation
  if (editUserForm) {
    FormValidation.formValidation(editUserForm, {
      fields: {
        name: {
          validators: {
            notEmpty: { message: 'Please enter full name' }
          }
        },
        email: {
          validators: {
            notEmpty: { message: 'Please enter your email' },
            emailAddress: { message: 'The value is not a valid email address' }
          }
        },
        phone_number: {
          validators: {
            notEmpty: { message: 'Please enter your phone number' },
            regexp: { regexp: /^[3][0-9]{9}$/, message: 'Phone number must be a valid Pakistani number starting with 3' }
          }
        },
        creditLimit: {
          validators: {
            notEmpty: { message: 'Please enter credit limit' },
            numeric: { message: 'Credit limit must be a number' }
          }
        },
        companyName: {
          validators: { notEmpty: { message: 'Please enter company name' } }
        }
      },
      plugins: {
        trigger: new FormValidation.plugins.Trigger(),
        bootstrap5: new FormValidation.plugins.Bootstrap5({
          eleValidClass: '',
          rowSelector: function (field, ele) { return '.mb-3'; }
        }),
        submitButton: new FormValidation.plugins.SubmitButton(),
        autoFocus: new FormValidation.plugins.AutoFocus()
      }
    }).on('core.form.valid', function () {
      var formData = new FormData(editUserForm);
      // Debug: Log form data
      for (var pair of formData.entries()) {
        console.log(pair[0] + ': ' + pair[1]);
      }
      $.ajax({
        url: editUserForm.action,
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        headers: { 'X-CSRFToken': getCsrfToken() },
        success: function (response) {
          if (response.status === 'success') {
            showAlert('edit-alert-container', response.message, 'success');
            $('#editUserModal').modal('hide');
            dt_user_table.DataTable().ajax.reload(null, false);
            editUserForm.reset();
          } else {
            showAlert('edit-alert-container', response.message, 'danger');
          }
        },
        error: function (xhr) {
          showAlert('edit-alert-container', xhr.responseJSON ? xhr.responseJSON.message : 'An error occurred.', 'danger');
        }
      });
    });
  }

  // Delete Form Validation
  if (deleteForm) {
    FormValidation.formValidation(deleteForm, {
      fields: {
        password: {
          validators: {
            notEmpty: { message: 'Please enter your password' }
          }
        }
      },
      plugins: {
        trigger: new FormValidation.plugins.Trigger(),
        bootstrap5: new FormValidation.plugins.Bootstrap5({
          eleValidClass: '',
          rowSelector: function (field, ele) { return '.mb-3'; }
        }),
        submitButton: new FormValidation.plugins.SubmitButton(),
        autoFocus: new FormValidation.plugins.AutoFocus()
      }
    }).on('core.form.valid', function () {
      $.ajax({
        url: deleteForm.action,
        type: 'POST',
        data: new FormData(deleteForm),
        processData: false,
        contentType: false,
        headers: { 'X-CSRFToken': getCsrfToken() },
        success: function (response) {
          if (response.status === 'success') {
            showAlert('delete-alert-container', response.message, 'success');
            $('#deleteModal').modal('hide');
            dt_user_table.DataTable().ajax.reload(null, false);
            deleteForm.reset();
          } else {
            showAlert('delete-alert-container', response.message, 'danger');
          }
        },
        error: function (xhr) {
          showAlert('delete-alert-container', xhr.responseJSON ? xhr.responseJSON.message : 'An error occurred.', 'danger');
        }
      });
    });
  }
})();