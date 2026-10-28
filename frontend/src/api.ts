const API = '/api'
export type CaseRecord = {id:string;name:string;reference:string;description:string;created_at:string;evidence_count:number}
export type EvidenceRecord = {id:string;case_id:string;original_filename:string;size_bytes:number;mime_type:string;original_sha256:string|null;collector_id:string;status:string;created_at:string;batch_id:string|null;source_id:string;source_name:string;source_url:string|null;source_scenario:string|null}
export type AuditRecord = {sequence:number;actor_id:string;action:string;case_id:string|null;evidence_id:string|null;outcome:string;reference:string|null;occurred_at:string;entry_hash:string}
export type UserRecord = {id:string;username:string;role:string;wallet_address:string|null;created_at:string}

export function token() { return localStorage.getItem('coc_token') }
export function fingerprintCode() { return sessionStorage.getItem('forenseal_fingerprint_code') }
export async function api<T>(path:string, init:RequestInit={}):Promise<T> {
  const headers = new Headers(init.headers)
  if (token()) headers.set('Authorization', `Bearer ${token()}`)
  if (fingerprintCode()) headers.set('X-Fingerprint-Code', fingerprintCode()!)
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type','application/json')
  const response = await fetch(`${API}${path}`, {...init,headers})
  if (!response.ok) { const payload = await response.json().catch(()=>({detail:response.statusText})); throw new Error(payload.detail || 'Request failed') }
  return response.json() as Promise<T>
}
