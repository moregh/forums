class Router {
    constructor() {
        this.routes = {};
        this.currentRoute = null;
        this.isNavigating = false;
        this.initialized = false;

        window.addEventListener('popstate', () => this.handleRoute());

        // Ensure state stays in sync with URL
        this.syncState();
    }

    syncState() {
        this.currentRoute = window.location.pathname;
        // Reset navigation flag if it's stuck
        if (this.isNavigating) {
            console.warn('Router was stuck in navigating state, resetting');
            this.isNavigating = false;
        }
    }

    register(path, handler) {
        this.routes[path] = handler;
    }

    navigate(path, pushState = true) {
        // Ensure we're in sync before navigating
        if (this.currentRoute !== window.location.pathname) {
            console.warn('Router state was out of sync, fixing');
            this.syncState();
        }

        if (this.isNavigating) return; // Prevent recursion

        if (pushState && path !== window.location.pathname) {
            history.pushState({}, '', path);
        }

        // Always handle route and sync currentRoute
        this.handleRoute();
    }

    handleRoute() {
        if (this.isNavigating) return; // Prevent recursion
        this.isNavigating = true;

        try {
            const path = window.location.pathname;

            // Always sync currentRoute with actual URL first
            this.currentRoute = path;

            let routeFound = false;
            for (const routePath in this.routes) {
                const regex = new RegExp('^' + routePath.replace(/:\w+/g, '([^/]+)') + '$');
                const match = path.match(regex);

                if (match) {
                    const params = {};
                    const paramNames = routePath.match(/:(\w+)/g) || [];
                    paramNames.forEach((param, index) => {
                        const paramName = param.substring(1);
                        params[paramName] = match[index + 1];
                    });

                    this.routes[routePath](params);
                    routeFound = true;
                    break;
                }
            }

            if (!routeFound && path !== '/') {
                history.replaceState({}, '', '/');
                if (this.routes['/']) {
                    this.routes['/']({});
                }
            } else if (!routeFound && path === '/') {
                if (this.routes['/']) {
                    this.routes['/']({});
                }
            }
        } catch (error) {
            console.error('Router error:', error);
        } finally {
            this.isNavigating = false;
            this.initialized = true;
        }
    }

    init() {
        if (!this.initialized) {
            this.handleRoute();
        }
    }
}