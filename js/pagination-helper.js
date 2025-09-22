/**
 * Simple pagination helper for the forum application
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
        const totalPages = Math.max(1, Math.ceil(totalItems / itemsPerPage));
        const validCurrentPage = Math.max(1, Math.min(currentPage, totalPages));

        return {
            currentPage: validCurrentPage,
            totalPages,
            totalItems,
            itemsPerPage,
            hasNext: validCurrentPage < totalPages,
            hasPrev: validCurrentPage > 1
        };
    }

    /**
     * Render pagination HTML with event delegation
     * @param {Object} pagination - Pagination metadata
     * @param {string} containerId - ID of container for event delegation
     * @returns {string} HTML string for pagination
     */
    static renderPagination(pagination, containerId = 'pagination-container') {
        if (pagination.totalPages <= 1) {
            return '';
        }

        const { currentPage, totalPages, hasNext, hasPrev } = pagination;

        let html = `<div class="pagination" id="${containerId}">`;

        // Previous button
        if (hasPrev) {
            html += `<button class="pagination-btn" data-page="${currentPage - 1}">← Previous</button>`;
        }

        // Current page info
        html += `<span class="pagination-info">Page ${currentPage} of ${totalPages}</span>`;

        // Next button
        if (hasNext) {
            html += `<button class="pagination-btn" data-page="${currentPage + 1}">Next →</button>`;
        }

        html += '</div>';
        return html;
    }

    /**
     * Set up event delegation for pagination buttons
     * @param {string} containerId - ID of pagination container
     * @param {Function} onPageChange - Callback function for page changes
     */
    static setupEventDelegation(containerId, onPageChange) {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Remove existing listeners
        container.removeEventListener('click', container._paginationHandler);

        // Add new listener
        container._paginationHandler = (event) => {
            if (event.target.classList.contains('pagination-btn')) {
                const page = parseInt(event.target.dataset.page, 10);
                if (page && onPageChange) {
                    onPageChange(page);
                    // Scroll to top after page change
                    setTimeout(() => {
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                    }, 100);
                }
            }
        };

        container.addEventListener('click', container._paginationHandler);
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
}