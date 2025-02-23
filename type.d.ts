declare global {
    type Env = {
        ID?: string;
        SRC_REGIONS?: string[];
        SRC_IPV4_RANGES?: string[];
        SRC_IPV6_RANGES?: string[];
        TARGETS?: string[];
        DEV?: any;
    };
}

export {};
