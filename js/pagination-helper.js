/**
 * Pagination helper utilities for the forum application
 * Handles pagination calculations, rendering, and navigation logic
 */
class PaginationHelper {
    /**
     * Calculate pagination metadata
     * @param {number} currentPage - Current page number (1-based)
     * @param {number} totalItems - Total number of items
     * @param {number} itemsPerPage - Items per page
     * @returns {Object} Pagination metadata
     */
    static calculatePagination(currentPage, totalItems, itemsPerPage = 20) {
        const totalPages = Math.ceil(totalItems / itemsPerPage);
        const offset = (currentPage - 1) * itemsPerPage;
        
        return {
            currentPage: Math.max(1, Math.min(currentPage, totalPages)),
            totalPages: Math.max(1, totalPages),
            totalItems,
            itemsPerPage,
            offset: Math.max(0, offset),
            hasNextPage: currentPage < totalPages,
            hasPrevPage: currentPage > 1,
            isFirstPage: currentPage === 1,
            isLastPage: currentPage === totalPages || totalPages === 0,
            startItem: totalItems === 0 ? 0 : offset + 1,
            endItem: Math.min(offset + itemsPerPage, totalItems)
        };
    }
    
    /**
     * Generate page numbers to display in pagination controls
     * @param {number} currentPage - Current page number
     * @param {number} totalPages - Total number of pages
     * @param {number} maxVisible - Maximum number of page buttons to show
     * @returns {Array} Array of page numbers to display
     */
    static generatePageNumbers(currentPage, totalPages, maxVisible = 7) {
        if (totalPages <= maxVisible) {
            return Array.from({ length: totalPages }, (_, i) => i + 1);
        }
        
        const pages = [];
        const halfVisible = Math.floor(maxVisible / 2);
        
        let start = Math.max(1, currentPage - halfVisible);
        let end = Math.min(totalPages, currentPage + halfVisible);
        
        // Adjust if we're near the beginning or end
        if (end - start + 1 < maxVisible) {
            if (start === 1) {
                end = Math.min(totalPages, start + maxVisible - 1);
            } else {
                start = Math.max(1, end - maxVisible + 1);
            }
        }
        
        // Always show first page
        if (start > 1) {
            pages.push(1);
            if (start > 2) {
                pages.push('...');
            }
        }
        
        // Add the main range
        for (let i = start; i <= end; i++) {
            pages.push(i);
        }
        
        // Always show last page
        if (end < totalPages) {
            if (end < totalPages - 1) {
                pages.push('...');
            }
            pages.push(totalPages);
        }
        
        return pages;
    }
    
    /**
     * Render pagination HTML
     * @param {Object} pagination - Pagination metadata
     * @param {Function} onPageChange - Callback function for page changes
     * @param {Object} options - Rendering options
     * @returns {string} HTML string for pagination
     */
    static renderPagination(pagination, onPageChange, options = {}) {
        const {
            showInfo = true,
            showFirstLast = true,
            maxVisible = 7,
            className = 'pagination',
            prevText = '← Previous',
            nextText = 'Next →',
            firstText = '« First',
            lastText = 'Last »'
        } = options;
        
        if (pagination.totalPages <= 1) {
            return '';
        }
        
        const { currentPage, totalPages, totalItems, startItem, endItem } = pagination;
        
        let html = `<div class="${className}">`;
        
        // Info text
        if (showInfo) {
            html += `<div class="pagination-info">
                Showing ${startItem}-${endItem} of ${totalItems} items
            </div>`;
        }
        
        html += '<div class="pagination-controls">';
        
        // First page button
        if (showFirstLast && currentPage > 2) {
            html += `<button class="pagination-btn" onclick="${onPageChange(1)}">${firstText}</button>`;
        }
        
        // Previous button
        if (pagination.hasPrevPage) {
            html += `<button class="pagination-btn" onclick="${onPageChange(currentPage - 1)}">${prevText}</button>`;
        }
        
        // Page numbers
        const pageNumbers = this.generatePageNumbers(currentPage, totalPages, maxVisible);
        
        pageNumbers.forEach(pageNum => {
            if (pageNum === '...') {
                html += '<span class="pagination-ellipsis">…</span>';
            } else {
                const isActive = pageNum === currentPage;
                const activeClass = isActive ? ' active' : '';
                const disabled = isActive ? ' disabled' : '';
                
                html += `<button class="pagination-btn${activeClass}" 
                         onclick="${isActive ? '' : onPageChange(pageNum)}"${disabled}>
                         ${pageNum}
                         </button>`;
            }
        });
        
        // Next button
        if (pagination.hasNextPage) {
            html += `<button class="pagination-btn" onclick="${onPageChange(currentPage + 1)}">${nextText}</button>`;
        }
        
        // Last page button
        if (showFirstLast && currentPage < totalPages - 1) {
            html += `<button class="pagination-btn" onclick="${onPageChange(totalPages)}">${lastText}</button>`;
        }
        
        html += '</div></div>';
        
        return html;
    }
    
    /**
     * Render simple pagination (just prev/next)
     * @param {Object} pagination - Pagination metadata
     * @param {Function} onPageChange - Callback function for page changes
     * @param {Object} options - Rendering options
     * @returns {string} HTML string for simple pagination
     */
    static renderSimplePagination(pagination, onPageChange, options = {}) {
        const {
            className = 'pagination-simple',
            prevText = '← Previous',
            nextText = 'Next →',
            showPageInfo = true
        } = options;
        
        if (pagination.totalPages <= 1) {
            return '';
        }
        
        const { currentPage, totalPages } = pagination;
        
        let html = `<div class="${className}">`;
        
        // Previous button
        if (pagination.hasPrevPage) {
            html += `<button class="pagination-btn" onclick="${onPageChange(currentPage - 1)}">${prevText}</button>`;
        }
        
        // Page info
        if (showPageInfo) {
            html += `<span class="pagination-info">Page ${currentPage} of ${totalPages}</span>`;
        }
        
        // Next button
        if (pagination.hasNextPage) {
            html += `<button class="pagination-btn" onclick="${onPageChange(currentPage + 1)}">${nextText}</button>`;
        }
        
        html += '</div>';
        
        return html;
    }
    
    /**
     * Calculate the page number where a specific item would appear
     * @param {number} itemIndex - 0-based index of the item
     * @param {number} itemsPerPage - Items per page
     * @returns {number} Page number (1-based)
     */
    static getPageForItem(itemIndex, itemsPerPage = 20) {
        return Math.floor(itemIndex / itemsPerPage) + 1;
    }
    
    /**
     * Calculate the page number for the last page of new content
     * @param {number} totalItems - Total number of items after adding new item
     * @param {number} itemsPerPage - Items per page
     * @returns {number} Page number where the new item would appear
     */
    static getLastPageForNewItem(totalItems, itemsPerPage = 20) {
        return Math.ceil(totalItems / itemsPerPage);
    }
    
    /**
     * Create a pagination state object for managing pagination in components
     * @param {number} initialPage - Initial page number
     * @param {number} itemsPerPage - Items per page
     * @returns {Object} Pagination state manager
     */
    static createPaginationState(initialPage = 1, itemsPerPage = 20) {
        return {
            currentPage: initialPage,
            itemsPerPage,
            totalItems: 0,
            
            setTotalItems(total) {
                this.totalItems = total;
                const maxPage = Math.ceil(total / this.itemsPerPage) || 1;
                if (this.currentPage > maxPage) {
                    this.currentPage = maxPage;
                }
            },
            
            setPage(page) {
                const maxPage = Math.ceil(this.totalItems / this.itemsPerPage) || 1;
                this.currentPage = Math.max(1, Math.min(page, maxPage));
            },
            
            nextPage() {
                const maxPage = Math.ceil(this.totalItems / this.itemsPerPage) || 1;
                if (this.currentPage < maxPage) {
                    this.currentPage++;
                }
            },
            
            prevPage() {
                if (this.currentPage > 1) {
                    this.currentPage--;
                }
            },
            
            firstPage() {
                this.currentPage = 1;
            },
            
            lastPage() {
                this.currentPage = Math.ceil(this.totalItems / this.itemsPerPage) || 1;
            },
            
            getPagination() {
                return PaginationHelper.calculatePagination(
                    this.currentPage,
                    this.totalItems,
                    this.itemsPerPage
                );
            }
        };
    }
    
    /**
     * Parse URL parameters for pagination
     * @param {URLSearchParams} searchParams - URL search parameters
     * @returns {Object} Parsed pagination parameters
     */
    static parseUrlParams(searchParams) {
        const page = parseInt(searchParams.get('page'), 10) || 1;
        const perPage = parseInt(searchParams.get('per_page'), 10) || 20;
        
        return {
            page: Math.max(1, page),
            perPage: Math.max(1, Math.min(100, perPage)) // Cap at 100 items per page
        };
    }
    
    /**
     * Update URL with pagination parameters
     * @param {number} page - Page number
     * @param {number} perPage - Items per page (optional)
     * @param {boolean} replace - Whether to replace current history entry
     */
    static updateUrl(page, perPage = null, replace = false) {
        const url = new URL(window.location);
        
        if (page > 1) {
            url.searchParams.set('page', page.toString());
        } else {
            url.searchParams.delete('page');
        }
        
        if (perPage && perPage !== 20) {
            url.searchParams.set('per_page', perPage.toString());
        } else {
            url.searchParams.delete('per_page');
        }
        
        if (replace) {
            window.history.replaceState({}, '', url);
        } else {
            window.history.pushState({}, '', url);
        }
    }
    
    /**
     * Create a debounced pagination function to prevent rapid page changes
     * @param {Function} callback - Function to call on page change
     * @param {number} delay - Debounce delay in milliseconds
     * @returns {Function} Debounced function
     */
    static createDebouncedPagination(callback, delay = 300) {
        let timeoutId;
        
        return function(page) {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => {
                callback(page);
            }, delay);
        };
    }
    
    /**
     * Calculate optimal items per page based on viewport height
     * @param {number} itemHeight - Average height of each item in pixels
     * @param {number} minItems - Minimum items per page
     * @param {number} maxItems - Maximum items per page
     * @returns {number} Optimal items per page
     */
    static calculateOptimalItemsPerPage(itemHeight = 100, minItems = 10, maxItems = 50) {
        const viewportHeight = window.innerHeight;
        const availableHeight = viewportHeight - 300; // Account for header, footer, pagination
        const optimalItems = Math.floor(availableHeight / itemHeight);
        
        return Math.max(minItems, Math.min(maxItems, optimalItems));
    }
}