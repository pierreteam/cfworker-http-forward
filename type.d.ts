declare global {
    type Env = {
        TOKEN?: string;
        SRC_REGIONS?: string[];
        SRC_IPV4_RANGES?: string[];
        SRC_IPV6_RANGES?: string[];
        TARGETS?: string[];
    };
}

export {};
