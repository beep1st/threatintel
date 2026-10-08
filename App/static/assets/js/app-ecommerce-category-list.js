'use strict';

// Comment editor
const commentEditor = document.querySelector('.comment-editor');
if (commentEditor) {
  new Quill(commentEditor, {
    modules: {
      toolbar: '.comment-toolbar'
    },
    placeholder: 'Write a Comment...',
    theme: 'snow'
  });
}

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

  var dt_category_list_table = $('.datatables-category-list');

  var select2 = $('.select2');
  if (select2.length) {
    select2.each(function () {
      var $this = $(this);
      $this.wrap('<div class="position-relative"></div>').select2({
        dropdownParent: $this.parent(),
        placeholder: $this.data('placeholder')
      });
    });
  }

  if (dt_category_list_table.length) {
    var dt_category = dt_category_list_table.DataTable({
      ajax: {
        url: '/CategoryList/data/',
        type: 'GET'
      },
      columns: [
        { data: '' },
        { data: 'id' },
        { data: 'categories' },
        { data: null }
      ],
      columnDefs: [
        {
          className: 'control',
          searchable: false,
          orderable: false,
          responsivePriority: 1,
          targets: 0,
          render: function () {
            return '';
          }
        },
        {
          targets: 1,
          orderable: false,
          searchable: false,
          responsivePriority: 4,
          checkboxes: true,
          render: function () {
            return '<input type="checkbox" class="dt-checkboxes form-check-input">';
          },
          checkboxes: {
            selectAllRender: '<input type="checkbox" class="form-check-input">'
          }
        },
        {
          targets: 2,
          responsivePriority: 2,
          render: function (data, type, full, meta) {
            var $name = full['categories'],
                $category_detail = full['category_detail'],
                $image = full['cat_image'],
                $id = full['id'];

            var $output = $image
              ? `<img src="${$image}" alt="Category-${$id}" class="rounded-2" height="32" width="32">`
              : `<span class="avatar-initial rounded-2 bg-label-secondary">${$name ? $name.charAt(0).toUpperCase() : 'C'}</span>`;

            return `
              <div class="d-flex align-items-center">
                <div class="avatar-wrapper me-3 rounded-2 bg-label-secondary">
                  <div class="avatar">${$output}</div>
                </div>
                <div class="d-flex flex-column justify-content-center">
                  <span class="text-heading text-wrap fw-medium">${$name}</span>
                  <span class="text-truncate mb-0 d-none d-sm-block"><small>${$category_detail}</small></span>
                </div>
              </div>`;
          }
        },
        {
          targets: 3,
          title: 'Actions',
          orderable: false,
          searchable: false,
          render: function (data, type, full, meta) {
            var $id = full['id'],
                $title = full['categories'],
                $description = full['category_detail'],
                $image = full['cat_image'];
            return `
              <div class="d-flex align-items-sm-center justify-content-sm-center">
                <button class="btn btn-icon btn-text-secondary rounded-pill waves-effect waves-light edit-category" data-id="${$id}" data-title="${$title}" data-description="${$description}" data-image="${$image}" data-bs-toggle="modal" data-bs-target="#editCategoryModal">
                  <i class="ti ti-edit"></i>
                </button>
                <button class="btn btn-icon btn-text-secondary rounded-pill waves-effect waves-light dropdown-toggle hide-arrow" data-bs-toggle="dropdown">
                  <i class="ti ti-dots-vertical ti-md"></i>
                </button>
                <div class="dropdown-menu dropdown-menu-end m-0">
                  <a href="javascript:void(0);" class="dropdown-item delete-category" data-id="${$id}" data-bs-toggle="modal" data-bs-target="#deleteCategoryModal">Delete</a>
                </div>
              </div>`;
          }
        }
      ],
      order: [[2, 'desc']],
      dom:
        '<"card-header d-flex flex-wrap py-0 flex-column flex-sm-row"' +
        '<f>' +
        '<"d-flex justify-content-center justify-content-md-end align-items-baseline"<"dt-action-buttons d-flex justify-content-center flex-md-row align-items-baseline"lB>>' +
        '>t' +
        '<"row mx-1"' +
        '<"col-sm-12 col-md-6"i>' +
        '<"col-sm-12 col-md-6"p>' +
        '>',
      lengthMenu: [7, 10, 20, 50, 70, 100],
      language: {
        sLengthMenu: '_MENU_',
        search: '',
        searchPlaceholder: 'Search Category',
        paginate: {
          next: '<i class="ti ti-chevron-right ti-sm"></i>',
          previous: '<i class="ti ti-chevron-left ti-sm"></i>'
        }
      },
      buttons: [
        {
          text: '<i class="ti ti-plus ti-xs me-0 me-sm-2"></i><span class="d-none d-sm-inline-block">Add Category</span>',
          className: 'add-new btn btn-primary ms-2 waves-effect waves-light',
          attr: {
            'data-bs-toggle': 'offcanvas',
            'data-bs-target': '#offcanvasEcommerceCategoryList'
          }
        }
      ],
      responsive: {
        details: {
          display: $.fn.dataTable.Responsive.display.modal({
            header: function (row) {
              var data = row.data();
              return 'Details of ' + data['categories'];
            }
          }),
          type: 'column',
          renderer: function (api, rowIdx, columns) {
            var data = $.map(columns, function (col) {
              return col.title !== ''
                ? `<tr data-dt-row="${col.rowIndex}" data-dt-column="${col.columnIndex}">
                    <td>${col.title}:</td>
                    <td class="ps-0">${col.data}</td>
                  </tr>`
                : '';
            }).join('');
            return data ? $('<table class="table"/><tbody />').append(data) : false;
          }
        }
      }
    });

    $('.dt-action-buttons').addClass('pt-0');
    $('.dataTables_filter').addClass('me-3 mb-sm-6 mb-0 ps-0');

    // Handle edit button click
    dt_category_list_table.on('click', '.edit-category', function () {
      var $button = $(this);
      var id = $button.data('id');
      var title = $button.data('title');
      var description = $button.data('description');
      var image = $button.data('image');

      $('#edit-category-id').val(id);
      $('#edit-category-title').val(title);
      $('#edit-category-description').val(description);
      $('#current-image').text(image ? image : 'No image');
      $('#edit-alert-container').empty(); // Clear previous alerts
    });

    // Handle delete button click
    dt_category_list_table.on('click', '.delete-category', function () {
      var $button = $(this);
      var id = $button.data('id');
      $('#delete-category-id').val(id);
      $('#delete-password').val(''); // Clear password field
      $('#delete-alert-container').empty(); // Clear previous alerts
    });
  }

  setTimeout(() => {
    $('.dataTables_filter .form-control').removeClass('form-control-sm').addClass('ms-0');
    $('.dataTables_length .form-select').removeClass('form-select-sm').addClass('ms-0');
  }, 300);
});

// Form validation for add, edit, and delete forms
(function () {
  // Add Category Form
  const addCategoryForm = document.getElementById('eCommerceCategoryListForm');
  if (addCategoryForm) {
    FormValidation.formValidation(addCategoryForm, {
      fields: {
        title: {
          validators: {
            notEmpty: {
              message: 'Please enter category title'
            }
          }
        },
        description: {
          validators: {
            notEmpty: {
              message: 'Please enter category description'
            }
          }
        },
        image: {
          validators: {
            file: {
              maxSize: 5242880,
              message: 'The selected file is not valid or exceeds 5MB'
            }
          }
        }
      },
      plugins: {
        trigger: new FormValidation.plugins.Trigger(),
        bootstrap5: new FormValidation.plugins.Bootstrap5({
          eleValidClass: 'is-valid',
          rowSelector: function () {
            return '.mb-6';
          }
        }),
        submitButton: new FormValidation.plugins.SubmitButton(),
        autoFocus: new FormValidation.plugins.AutoFocus()
      }
    }).on('core.form.valid', function () {
      $.ajax({
        url: addCategoryForm.action,
        type: 'POST',
        data: new FormData(addCategoryForm),
        processData: false,
        contentType: false,
        headers: {
          'X-CSRFToken': getCsrfToken()
        },
        success: function (response) {
          if (response.status === 'success') {
            showAlert('add-alert-container', response.message, 'success');
            $('#offcanvasEcommerceCategoryList').offcanvas('hide');
            dt_category_list_table.DataTable().ajax.reload(null, false); // Keep pagination
            addCategoryForm.reset();
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

  // Edit Category Form
  const editCategoryForm = document.getElementById('editCategoryForm');
  if (editCategoryForm) {
    FormValidation.formValidation(editCategoryForm, {
      fields: {
        title: {
          validators: {
            notEmpty: {
              message: 'Please enter category title'
            }
          }
        },
        description: {
          validators: {
            notEmpty: {
              message: 'Please enter category description'
            }
          }
        },
        image: {
          validators: {
            file: {
              maxSize: 5242880,
              message: 'The selected file is not valid or exceeds 5MB'
            }
          }
        }
      },
      plugins: {
        trigger: new FormValidation.plugins.Trigger(),
        bootstrap5: new FormValidation.plugins.Bootstrap5({
          eleValidClass: 'is-valid',
          rowSelector: function () {
            return '.mb-3';
          }
        }),
        submitButton: new FormValidation.plugins.SubmitButton(),
        autoFocus: new FormValidation.plugins.AutoFocus()
      }
    }).on('core.form.valid', function () {
      $.ajax({
        url: editCategoryForm.action,
        type: 'POST',
        data: new FormData(editCategoryForm),
        processData: false,
        contentType: false,
        headers: {
          'X-CSRFToken': getCsrfToken()
        },
        success: function (response) {
          if (response.status === 'success') {
            showAlert('edit-alert-container', response.message, 'success');
            $('#editCategoryModal').modal('hide');
            dt_category_list_table.DataTable().ajax.reload(null, false); // Keep pagination
            editCategoryForm.reset();
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

  // Delete Category Form
  const deleteCategoryForm = document.getElementById('deleteCategoryForm');
  if (deleteCategoryForm) {
    FormValidation.formValidation(deleteCategoryForm, {
      fields: {
        password: {
          validators: {
            notEmpty: {
              message: 'Please enter your password'
            }
          }
        }
      },
      plugins: {
        trigger: new FormValidation.plugins.Trigger(),
        bootstrap5: new FormValidation.plugins.Bootstrap5({
          eleValidClass: 'is-valid',
          rowSelector: function () {
            return '.mb-3';
          }
        }),
        submitButton: new FormValidation.plugins.SubmitButton(),
        autoFocus: new FormValidation.plugins.AutoFocus()
      }
    }).on('core.form.valid', function () {
      $.ajax({
        url: deleteCategoryForm.action,
        type: 'POST',
        data: new FormData(deleteCategoryForm),
        processData: false,
        contentType: false,
        headers: {
          'X-CSRFToken': getCsrfToken()
        },
        success: function (response) {
          if (response.status === 'success') {
            showAlert('delete-alert-container', response.message, 'success');
            $('#deleteCategoryModal').modal('hide');
            dt_category_list_table.DataTable().ajax.reload(null, false); // Keep pagination
            deleteCategoryForm.reset();
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