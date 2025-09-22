class ForumState {
    constructor() {
        this.listeners = {};
        this.state = {
            user: null,
            boards: [],
            currentBoard: null,
            currentThread: null,
            threads: [],
            posts: [],
            loading: false,
            error: null
        };
    }

    subscribe(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }

    emit(event, data) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(callback => callback(data));
        }
    }

    setState(updates) {
        const oldState = { ...this.state };
        this.state = { ...this.state, ...updates };
        
        Object.keys(updates).forEach(key => {
            if (oldState[key] !== this.state[key]) {
                this.emit(`${key}Changed`, this.state[key]);
            }
        });
        
        this.emit('stateChanged', this.state);
    }

    getState() {
        return this.state;
    }
}