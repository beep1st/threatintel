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

  var dt_product_table = $('.datatables-products'),
    productAdd = '/AddProduct/',
    statusObj = {
      true: { title: 'Published', class: 'bg-label-success' },
      false: { title: 'Inactive', class: 'bg-label-danger' }
    };

  if (dt_product_table.length) {
    // Check if DataTable is already initialized
    if ($.fn.DataTable.isDataTable(dt_product_table)) {
      dt_product_table.DataTable().destroy();
    }

    var dt_products = dt_product_table.DataTable({
      ajax: {
        url: '/product_list_api/',
        dataSrc: 'data',
        error: function (xhr, error, thrown) {
          console.error('DataTable AJAX error:', error, thrown);
          showAlert('DataTables_Table_0_wrapper', 'Failed to load product data.', 'danger');
        }
      },
      columns: [
        { data: 'id' },
        { data: 'id' },
        { data: 'Name' },
        { data: 'category_name' },
        { data: 'stock' },
        { data: 'sku' },
        { data: 'price' },
        { data: 'Qty' },
        { data: 'is_active' },
        { data: '' }
      ],
      columnDefs: [
        {
          className: 'control',
          searchable: false,
          orderable: false,
          responsivePriority: 2,
          targets: 0,
          render: function () {
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
          responsivePriority: 1,
          render: function (data, type, full, meta) {
            var $name = full['Name'] || 'Unknown',
              $id = full['id'],
              $image = full['image'];
            var $output = $image
              ? '<img src="' + $image + '" alt="Product-' + $id + '" class="rounded-2">'
              : '<span class="avatar-initial rounded-2 bg-label-secondary">' + ($name.match(/\b\w/g) || []).slice(0, 2).join('').toUpperCase() + '</span>';
            return `
              <div class="d-flex justify-content-start align-items-center product-name">
                <div class="avatar-wrapper">
                  <div class="avatar avatar me-4 rounded-2 bg-label-secondary">${$output}</div>
                </div>
                <div class="d-flex flex-column">
                  <h6 class="text-nowrap mb-0">${$name}</h6>
                </div>
              </div>`;
          }
        },
        {
          targets: 3,
          responsivePriority: 5,
          render: function (data, type, full, meta) {
            var $category = full['category_name'] || 'N/A';
            return '<span class="text-heading">' + $category + '</span>';
          }
        },
        {
          targets: 4,
          orderable: false,
          responsivePriority: 3,
          render: function (data, type, full, meta) {
            var $stock = full['stock'] || 0;
            var stockSwitchObj = {
              0: '<label class="switch switch-primary switch-sm"><input type="checkbox" class="switch-input" /><span class="switch-toggle-slider"><span class="switch-off"></span></span></label>',
              In_Stock: '<label class="switch switch-primary switch-sm"><input type="checkbox" class="switch-input" checked /><span class="switch-toggle-slider"><span class="switch-on"></span></span></label>'
            };
            return '<span class="text-truncate">' + stockSwitchObj[$stock > 0 ? 'In_Stock' : 0] + '<span class="d-none">' + ($stock > 0 ? 'In Stock' : 'Out of Stock') + '</span></span>';
          }
        },
        {
          targets: 5,
          render: function (data, type, full, meta) {
            return '<span>' + (full['sku'] || 'N/A') + '</span>';
          }
        },
        {
          targets: 6,
          render: function (data, type, full, meta) {
            return '<span>' + (full['price'] || '0.00') + '</span>';
          }
        },
        {
          targets: 7,
          responsivePriority: 4,
          render: function (data, type, full, meta) {
            return '<span>' + (full['Qty'] || '0') + '</span>';
          }
        },
        {
          targets: 8,
          render: function (data, type, full, meta) {
            var $status = full['is_active'];
            return '<span class="badge ' + statusObj[$status].class + '">' + statusObj[$status].title + '</span>';
          }
        },
        {
          targets: -1,
          title: 'Actions',
          searchable: false,
          orderable: false,
          render: function (data, type, full, meta) {
            var description = full['description'] ? String(full['description']).replace(/"/g, '&quot;') : '';
            return `
              <div class="d-flex align-items-center">
                <a href="javascript:;" class="btn btn-icon btn-text-secondary waves-effect waves-light rounded-pill edit-record" 
                   data-product-id="${full['id']}" 
                   data-name="${full['Name'] ? String(full['Name']).replace(/"/g, '&quot;') : ''}" 
                   data-sku="${full['sku'] ? String(full['sku']).replace(/"/g, '&quot;') : ''}" 
                   data-price="${full['price'] || ''}" 
                   data-stock="${full['stock'] || ''}" 
                   data-category="${full['category'] || ''}" 
                   data-is-active="${full['is_active']}" 
                   data-description="${description}" 
                   data-image="${full['image'] || ''}" 
                   data-bs-toggle="modal" 
                   data-bs-target="#editProductModal">
                  <i class="ti ti-edit ti-md"></i>
                </a>
                <a href="javascript:;" class="btn btn-icon btn-text-secondary waves-effect waves-light rounded-pill delete-record" 
                   data-product-id="${full['id']}" 
                   data-bs-toggle="modal" 
                   data-bs-target="#deleteModal">
                  <i class="ti ti-trash ti-md"></i>
                </a>
              </div>`;
          }
        }
      ],
      order: [[2, 'asc']],
      dom:
        '<"card-header d-flex border-top rounded-0 flex-wrap py-0 flex-column flex-md-row align-items-start"' +
        '<"me-5 ms-n4 pe-5 mb-n6 mb-md-0"f>' +
        '<"d-flex justify-content-start justify-content-md-end align-items-baseline"<"dt-action-buttons d-flex flex-column align-items-start align-items-sm-center justify-content-sm-center pt-0 gap-sm-4 gap-sm-0 flex-sm-row"lB>>' +
        '>t' +
        '<"row"<"col-sm-12 col-md-6"i><"col-sm-12 col-md-6"p>>',
      lengthMenu: [7, 10, 20, 50, 70, 100],
      language: {
        sLengthMenu: '_MENU_',
        search: '',
        searchPlaceholder: 'Search Product',
        info: 'Displaying _START_ to _END_ of _TOTAL_ entries',
        paginate: {
          next: '<i class="ti ti-chevron-right ti-sm"></i>',
          previous: '<i class="ti ti-chevron-left ti-sm"></i>'
        }
      },
      buttons: [
        {
          extend: 'collection',
          className: 'btn btn-label-secondary dropdown-toggle me-4 waves-effect waves-light',
          text: '<i class="ti ti-upload me-1 ti-xs"></i>Export',
          buttons: [
            { extend: 'print', text: '<i class="ti ti-printer me-2"></i>Print', className: 'dropdown-item', exportOptions: { columns: [1, 2, 3, 4, 5, 6, 7] } },
            { extend: 'csv', text: '<i class="ti ti-file me-2"></i>Csv', className: 'dropdown-item', exportOptions: { columns: [1, 2, 3, 4, 5, 6, 7] } },
            { extend: 'excel', text: '<i class="ti ti-file-export me-2"></i>Excel', className: 'dropdown-item', exportOptions: { columns: [1, 2, 3, 4, 5, 6, 7] } },
            { extend: 'pdf', text: '<i class="ti ti-file-text me-2"></i>Pdf', className: 'dropdown-item', exportOptions: { columns: [1, 2, 3, 4, 5, 6, 7] } },
            { extend: 'copy', text: '<i class="ti ti-copy me-2"></i>Copy', className: 'dropdown-item', exportOptions: { columns: [1, 2, 3, 4, 5, 6, 7] } }
          ]
        },
        {
          text: '<i class="ti ti-plus me-0 me-sm-1 ti-xs"></i><span class="d-none d-sm-inline-block">Add Product</span>',
          className: 'add-new btn btn-primary ms-2 ms-sm-0 waves-effect waves-light',
          action: function () {
            window.location.href = productAdd;
          }
        }
      ],
      responsive: {
        details: {
          display: $.fn.dataTable.Responsive.display.modal({
            header: function (row) {
              var data = row.data();
              return 'Details of ' + (data['Name'] || 'Unknown');
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
        // Clear existing filter dropdowns to prevent duplicates
        $('.product_status, .product_category, .product_stock').empty();

        this.api()
          .columns(8)
          .every(function () {
            var column = this;
            var select = $('<select id="ProductStatus" class="form-select text-capitalize"><option value="">Status</option></select>')
              .appendTo('.product_status')
              .on('change', function () {
                var val = $.fn.dataTable.util.escapeRegex($(this).val());
                column.search(val ? '^' + val + '$' : '', true, false).draw();
              });
            Object.keys(statusObj).forEach(function (key) {
              select.append('<option value="' + statusObj[key].title + '">' + statusObj[key].title + '</option>');
            });
          });
        this.api()
  .columns(3)
  .every(function () {
    var column = this;
    var select = $('<select id="ProductCategory" class="form-select text-capitalize"><option value="">Category</option></select>')
      .appendTo('.product_category')
      .on('change', function () {
        var val = $.fn.dataTable.util.escapeRegex($(this).val());
        column.search(val ? '^' + val + '$' : '', true, false).draw();
      });

    var seen = {};
    column.data().each(function (d) {
      var category = (d || '').trim();
      if (category && !seen[category]) {
        seen[category] = true;
        select.append('<option value="' + category + '">' + category + '</option>');
      }
    });
  });

        this.api()
          .columns(4)
          .every(function () {
            var column = this;
            var select = $('<select id="ProductStock" class="form-select text-capitalize"><option value="">Stock</option></select>')
              .appendTo('.product_stock')
              .on('change', function () {
                var val = $.fn.dataTable.util.escapeRegex($(this).val());
                column.search(val ? '^' + val + '$' : '', true, false).draw();
              });
            select.append('<option value="In Stock">In Stock</option><option value="Out of Stock">Out of Stock</option>');
          });
      }
    });
    $('.dataTables_length').addClass('mx-n2');
    $('.dt-buttons').addClass('d-flex flex-wrap mb-6 mb-sm-0');

    // Edit Record
    dt_product_table.on('click', '.edit-record', function () {
      var $row = $(this);
      $('#edit-product-id').val($row.data('product-id'));
      $('#edit-product-name').val($row.data('name'));
      $('#edit-product-sku').val($row.data('sku'));
      $('#edit-product-price').val($row.data('price'));
      $('#edit-product-stock').val($row.data('stock'));
      $('#edit-product-category').val($row.data('category')).trigger('change');
      $('#edit-product-is-active').prop('checked', $row.data('is-active') === true);
      var quill = new Quill('#edit-product-description', {
        theme: 'snow',
        modules: {
          toolbar: [
            ['bold', 'italic', 'underline'],
            [{ 'list': 'ordered' }, { 'list': 'bullet' }],
            ['link', 'image']
          ]
        }
      });
      quill.root.innerHTML = $row.data('description') || '';
      $('#editProductForm').on('submit', function () {
        $('#edit-description-hidden').val(quill.root.innerHTML);
      });
      var editDropzone = new Dropzone('#edit-dropzone', {
        url: '/edit-product/' + $row.data('product-id') + '/',
        autoProcessQueue: false,
        maxFiles: 1,
        acceptedFiles: 'image/*',
        addRemoveLinks: true,
        init: function () {
          if ($row.data('image')) {
            var mockFile = { name: 'Current Image', size: 12345 };
            this.emit('addedfile', mockFile);
            this.emit('thumbnail', mockFile, $row.data('image'));
            this.emit('complete', mockFile);
          }
          this.on('success', function (file, response) {
            var formData = new FormData(document.getElementById('editProductForm'));
            formData.append('image', file);
            submitEditForm(formData, $row.data('product-id'));
          });
          this.on('error', function (file, errorMessage) {
            showAlert('edit-alert-container', 'Image upload failed: ' + errorMessage, 'danger');
          });
        }
      });
      $('#editProductForm').off('submit').on('submit', function (e) {
        e.preventDefault();
        var formData = new FormData(this);
        if (editDropzone.getQueuedFiles().length > 0) {
          editDropzone.processQueue();
        } else {
          submitEditForm(formData, $row.data('product-id'));
        }
      });
    });

    function submitEditForm(formData, productId) {
      $.ajax({
        url: '/edit-product/' + productId + '/',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        headers: { 'X-CSRFToken': getCsrfToken() },
        success: function (response) {
          if (response.status === 'success') {
            showAlert('edit-alert-container', response.message, 'success');
            $('#editProductModal').modal('hide');
            dt_products.ajax.reload();
          } else {
            showAlert('edit-alert-container', response.message, 'danger');
          }
        },
        error: function (xhr) {
          showAlert('edit-alert-container', xhr.responseJSON ? xhr.responseJSON.message : 'An error occurred.', 'danger');
        }
      });
    }

    // Delete Record
    dt_product_table.on('click', '.delete-record', function () {
      $('#delete-product-id').val($(this).data('product-id'));
      $('#deleteForm').attr('action', '/delete-product/' + $(this).data('product-id') + '/');
      $('#deleteForm').off('submit').on('submit', function (e) {
        e.preventDefault();
        $.ajax({
          url: $(this).attr('action'),
          type: 'POST',
          data: new FormData(this),
          processData: false,
          contentType: false,
          headers: { 'X-CSRFToken': getCsrfToken() },
          success: function (response) {
            if (response.status === 'success') {
              showAlert('delete-alert-container', response.message, 'success');
              $('#deleteModal').modal('hide');
              dt_products.ajax.reload();
            } else {
              showAlert('delete-alert-container', response.message, 'danger');
            }
          },
          error: function (xhr) {
            showAlert('delete-alert-container', xhr.responseJSON ? xhr.responseJSON.message : 'An error occurred.', 'danger');
          }
        });
      });
    });
  }
});