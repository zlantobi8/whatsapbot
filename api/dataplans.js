import datas from './myjs.json' assert { type: 'json' };

// Extract each network plan
export const MTN_PLAN = datas.MTN_PLAN;
export const GLO_PLAN = datas.GLO_PLAN;
export const AIRTEL_PLAN = datas.AIRTEL_PLAN;
export const MOBILE9_PLAN = datas['9MOBILE_PLAN'];

// Map network IDs to their respective plans
export const DATA_PLANS = {
  1: MTN_PLAN.ALL,
  2: AIRTEL_PLAN.ALL,
  3: GLO_PLAN.ALL,
  4: MOBILE9_PLAN.ALL
};
