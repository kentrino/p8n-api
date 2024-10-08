export type TypedResponse<T = unknown> = Omit<Response, "json"> & {
  json(): Promise<T>
}
