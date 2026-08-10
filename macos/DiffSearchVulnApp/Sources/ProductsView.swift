import SwiftUI

struct ProductsView: View {
    @Environment(AppModel.self) private var model
    @State private var isPresentingNewProduct = false

    var body: some View {
        Group {
            if model.products.isEmpty && !model.isLoadingProducts {
                ContentUnavailableView {
                    Label("No Products", systemImage: "shippingbox")
                } description: {
                    Text("Add an application or platform whose releases you want to track.")
                } actions: {
                    Button("Add Product") {
                        isPresentingNewProduct = true
                    }
                    .buttonStyle(.borderedProminent)
                }
            } else {
                Table(model.products) {
                    TableColumn("Product", value: \.name)
                    TableColumn("Vendor") { product in
                        Text(product.vendor ?? "—")
                            .foregroundStyle(product.vendor == nil ? .secondary : .primary)
                    }
                    TableColumn("Created") { product in
                        Text(product.createdAt)
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                .overlay {
                    if model.isLoadingProducts {
                        ProgressView()
                    }
                }
            }
        }
        .navigationTitle("Products")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    model.refreshProducts()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                Button {
                    isPresentingNewProduct = true
                } label: {
                    Label("Add Product", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $isPresentingNewProduct) {
            NewProductSheet(isPresented: $isPresentingNewProduct)
                .environment(model)
        }
    }
}

struct NewProductSheet: View {
    @Environment(AppModel.self) private var model
    @Binding var isPresented: Bool
    @State private var name = ""
    @State private var vendor = ""
    @State private var isSaving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Add Product")
                .font(.title2.weight(.semibold))
            Form {
                TextField("Name", text: $name)
                TextField("Vendor", text: $vendor)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) {
                    isPresented = false
                }
                Button("Add") {
                    isSaving = true
                    Task {
                        let created = await model.createProduct(
                            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                            vendor: vendor.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
                        )
                        isSaving = false
                        if created { isPresented = false }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isSaving)
            }
        }
        .padding(24)
        .frame(width: 440)
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
